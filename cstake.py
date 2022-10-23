import datetime
from os import getenv
from typing import List, Literal, Optional

from pycardano import (
    Address,
    AlonzoMetadata,
    AuxiliaryData,
    InvalidBefore,
    Metadata,
    ScriptAll,
    ScriptPubkey,
    Transaction,
    TransactionWitnessSet,
    wallet,
)
from pymongo import MongoClient


def lock(
    address: str,
    seconds: int,
    lovelace: Optional[int] = None,
    assets: Optional[List[dict]] = None,
    network: Optional[Literal["mainnet", "preprod", "preview"]] = "mainnet",
    private: Optional[bool] = False,
):
    """Lock Tokens in a Script Address for a certain amount of time.
    Only the user can sign the transaction to withdraw the tokens.

    Args:
        address (str): Address of the user who is locking the assets
        seconds (int): Number of seconds for which the assets will be locked
        lovelace (Optional[int], optional): Amount of Lovelace to lock. Defaults to the minimum ada needed to lock the tokens.
        assets (Optional[List[dict]], optional): Tokens to lock. Should be a dict of policies of the format
            {
                "policy_id":
                    {
                        "asset_name": amount,
                        "asset_2_name", amount_2
                    }
            }, ...
            Defaults to None.
        network (Optional[Enum["mainnet", "preprod", "preview"]], optional): Network on which to perform the staking. Defaults to "mainnet".
    """

    user = wallet.Wallet("user", address, network=network)

    # stake_address = user.stake_address
    # A policy that requires a signature from the payment address we generated above
    pub_key_policy = ScriptPubkey(user.verification_key_hash)

    # A time policy that locks until `seconds` have passed
    last_block_slot = user.context.last_block_slot
    policy_open_slot = last_block_slot + int(seconds)
    must_after_slot = InvalidBefore(policy_open_slot)

    # Combine two policies using ScriptAll policy
    policy = ScriptAll([pub_key_policy, must_after_slot])

    # Calculate policy ID, which is the hash of the policy
    policy_id = policy.hash()
    policy_address = Address(policy_id, network=user.address.network)

    # create an address with the policy payment hash and user's stake address
    if user.stake_address:
        policy_wallet = wallet.Wallet(
            "policy",
            address=Address(
                policy_address.payment_part,
                user.address.staking_part,
                network=user.address.network,
            ),
            network=user.network,
        )
    else:
        policy_wallet = wallet.Wallet(
            "policy", address=policy_address.payment_part, network=user.network
        )

    # draft the transaction
    if assets:
        assets = [
            wallet.Token(policy_id, name=token_name, amount=token_amount)
            for policy_id, info in assets.items()
            for token_name, token_amount in info.items()
        ]

    metadata = {
        4242: {"sig": str(user.verification_key_hash), "after": policy_open_slot}
    }

    tx_body = user.transact(
        inputs=user,
        outputs=wallet.Output(
            policy_wallet, wallet.Lovelace(int(lovelace)), tokens=assets
        ),
        signers=[user],
        other_metadata=metadata,
        submit=False,
    )

    tx = Transaction(tx_body, TransactionWitnessSet())

    info = {
        "_id": tx.transaction_body.hash().hex(),
        "tx": tx.to_cbor(),
        "sig": str(user.verification_key_hash),
        "after": policy_open_slot,
        "seconds": seconds,
        "lovelace": lovelace,
        "assets": assets,
        "last_block": last_block_slot,
        "network": network,
        "gen_time": int(datetime.datetime.utcnow().timestamp()),
        "submitted": False,
        "withdrawn": False,
    }

    if not private:
        mongo_client = MongoClient(getenv("CSTAKE_MONGO_URI"))
        db = mongo_client[getenv("CSTAKE_MONGO_DB")]
        collection = db[str(user.verification_key_hash)]

        collection.insert_one(info)

    # store in database:
    return info


def sign(tx: str, witness: str, metadata: Optional[dict], private: Optional[bool] = False):

    tx = Transaction.from_cbor(tx)
    witness = TransactionWitnessSet.from_cbor(witness)

    if metadata:
        auxiliary_data = AuxiliaryData(AlonzoMetadata(metadata=Metadata(metadata)))

        tx.auxiliary_data = auxiliary_data

    tx.transaction_witness_set = witness

    return tx.to_cbor(), tx.transaction_body.hash().hex()


def withdraw():

    pass
