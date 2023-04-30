"""Reads a deposit data directory along with the deposit data file and the keystore files in order
to validate they are correct, no validator is active and we are double depositing. And finally 
submits the transaction by sending a transaction.

Stakefish contract addy: https://etherscan.io/address/0x0194512e77d798e4871973d9cb9d7ddfc0ffd801
"""
import json
import logging
from pathlib import Path
import requests
from requests.exceptions import HTTPError

from .args import parse_args
from .onchain import perform_deposit

logger = logging.getLogger("eth_staking_helper.__main__")

def parse_deposit_data(path, withdrawal_address):
    with open(path, "r") as json_file:
        data = json.load(json_file)

    return_data = {"validators": {}}
    pubkeys_field = ""
    signatures_field = ""
    deposit_data_roots = []
    if withdrawal_address.startswith("0x"):
        withdrawal_address = withdrawal_address[2:]
    expected_credentials = "010000000000000000000000" + withdrawal_address.lower()
    for validator in data:
        pubkey = validator["pubkey"]
        withdrawal_credentials = validator["withdrawal_credentials"]
        if withdrawal_credentials != expected_credentials:
            raise ValueError(
                f"Expected {expected_credentials}, but found {withdrawal_credentials=}"
            )

        signature = validator["signature"]
        deposit_data_root = validator["deposit_data_root"]
        if pubkey in return_data["validators"]:
            logger.error("Duplicate pubkey, skipping. (%s)", pubkey)
            continue

        pubkeys_field += pubkey
        signatures_field += signature
        deposit_data_roots.append("0x" + deposit_data_root)

        return_data["validators"][pubkey] = {
            "withdrawal_credentials": withdrawal_credentials,
            "signature": signature,
            "deposit_data_root": deposit_data_root,
        }

    return_data["pubkeys"] = pubkeys_field
    return_data["withdrawals"] = expected_credentials
    return_data["signatures"] = signatures_field
    return_data["deposit_data_roots"] = deposit_data_roots
    return return_data


def check_beaconchain(return_data):
    """Check with beaconchain that none of the public keys of the validators have had a deposit.

    Protect the user from making a double deposit.
    """
    if len(return_data["validators"]) > 100:
        raise ValueError("Number of validators exceeds batch contract limit of 100 validators")

    args = ",".join(return_data["validators"].keys())
    response = requests.get(f"https://beaconcha.in/api/v1/validator/{args}/deposits")
    if response.status_code != 200:
        raise HTTPError(f"Requested beaconchain validation and call failed with: {response.text}")

    result = response.json()
    deposited_pubkeys = [deposit["publickey"] for deposit in response.json()["data"]]
    if len(deposited_pubkeys) > 0:
        for pubkey in deposited_pubkeys:
            logging.error("Pubkey %s has already been deposited", pubkey)
        raise ValueError("One or more pubkeys have already been deposited")

    logging.info("\n-- Checked beaconchain for validator existence!\n")


def check_keystore(path, return_data):
    with open(path, "r") as json_file:
        data = json.load(json_file)
        if data["pubkey"] not in return_data["validators"]:
            KeyError(
                f'{data["pubkey"]} from keystore file {path} was not found in deposit data'
            )


def iterate_files(
    data_dir, withdrawal_address, should_check_keystores, should_check_beaconchain
):
    return_data = {}
    for path in data_dir.iterdir():
        if path.name.startswith("deposit_data") or path.name.startswith("deposit-data"):
            return_data = parse_deposit_data(path, withdrawal_address)

    if not return_data:
        ValueError("Did not find deposit data in the directory")

    if should_check_keystores:
        for path in data_dir.iterdir():
            if path.name.startswith("keystore-"):
                check_keystore(path, return_data)

        logging.info("\n-- Checked keystore files!\n")

    if should_check_beaconchain:
        check_beaconchain(return_data)

    return return_data


def main():
    args = parse_args()
    data_dir = Path(args.data_dir)
    if not data_dir.is_dir():
        NotADirectoryError(f"Path {data_dir} is not a directory")

    data = iterate_files(
        data_dir=data_dir,
        withdrawal_address=args.withdrawal_address,
        should_check_keystores=args.check_keystores,
        should_check_beaconchain=args.check_beaconchain,
    )
    logging.info("pubkeys: %s", data["pubkeys"])
    logging.info("withdrawal_credentials: %s", data["withdrawals"])
    logging.info("signatures: %s", data["signatures"])
    logging.info("deposit_data_roots: %s", data["deposit_data_roots"])

    if args.execute_transaction or args.only_estimate_gas:
        perform_deposit(
            only_estimate_gas=args.only_estimate_gas,
            rpc_endpoint=args.rpc_endpoint,
            from_address=args.from_address,
            pubkeys=data["pubkeys"],
            withdrawal_credentials=data["withdrawals"],
            signatures=data["signatures"],
            deposit_data_roots=data["deposit_data_roots"],
            max_fee=args.max_fee,
            max_priority_fee=args.max_priority_fee,
        )


if __name__ == "__main__":
    main()
