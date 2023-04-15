import asyncio
import json
import logging
import os
import sys
import time
import datetime

from aiohttp import ClientError

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.agent import (  # noqa:E402
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class IssuerAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        cred_type: str = "",
        endorser_role: str = None,
        revocation: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Issuer",
            no_auto=no_auto,
            cred_type=cred_type,
            endorser_role=endorser_role,
            revocation=revocation,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # TODO define a dict to hold credential attributes
        # based on cred_def_id
        self.cred_attrs = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def generate_credential_offer_tier1(self, aip, cred_type, cred_def_id, exchange_tracing, connection_id):

        if aip == 20:
            if cred_type == CRED_FORMAT_JSON_LD:
                offer_request = {
                    "connection_id": connection_id,
                    "filter": {
                        "ld_proof": {
                            "credential": {
                                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://w3id.org/citizenship/v1",
                                    "https://schema.org/docs/jsonldcontext.json",
                                    "https://w3id.org/security/bbs/v1",
                                ],
                                "type": [
                                    "VerifiableCredential",
                                    "PermanentResident",
                                ],
                                "id": "https://credential.example.com/product/1",
                                "issuer": self.did,
                                "issuanceDate": "2020-01-01T12:00:00Z",
                                "credentialSubject": {
                                    "type": ["Product"],
                                    "serialNumber": "111",
                                    "co2": 1000,
                                    "previousTiers": {
                                        "@type": "ItemList",
                                        "itemListElement": [
                                            {
                                                "@type": "ListItem",
                                                "position": 1,
                                                "item": {
                                                    "id": "https://credential.example.com/product/2",
                                                    "description": "Product2",
                                                    "holder": {
                                                        "id": "https://credential.example.com/holder/2",
                                                        "name": "tier2",
                                                    }
                                                }
                                            },
                                            {
                                                "@type": "ListItem",
                                                "position": 2,
                                                "item": {
                                                    "id": "https://credential.example.com/product/3",
                                                    "description": "Product2",
                                                    "holder": {
                                                        "id": "https://credential.example.com/holder/3",
                                                        "name": "tier2",
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                },
                            },
                            "options": {"proofType": SIG_TYPE_BLS},
                        }
                    },
                }
                return offer_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_credential_offer_tier2(self, aip, cred_type, cred_def_id, exchange_tracing, connection_id):

        if aip == 20:
            if cred_type == CRED_FORMAT_JSON_LD:
                offer_request = {
                    "connection_id": connection_id,
                    "filter": {
                        "ld_proof": {
                            "credential": {
                                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://w3id.org/citizenship/v1",
                                    "https://schema.org/docs/jsonldcontext.json",
                                    "https://w3id.org/security/bbs/v1",
                                ],
                                "type": [
                                    "VerifiableCredential",
                                    "PermanentResident",
                                ],
                                "id": "https://credential.example.com/product/2",
                                "issuer": self.did,
                                "issuanceDate": "2020-01-01T12:00:00Z",
                                "credentialSubject": {
                                    "type": ["Product"],
                                    "serialNumber": "222",
                                    "co2": 300,
                                    "previousTiers": {
                                    }
                                },
                            },
                            "options": {"proofType": SIG_TYPE_BLS},
                        }
                    },
                }
                return offer_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")


async def main(args):
    issuer_agent = await create_agent_with_args(args, ident="issuer")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {issuer_agent.wallet_type})"
                if issuer_agent.wallet_type
                else ""
            )
        )
        agent = IssuerAgent(
            "issuer.agent",
            issuer_agent.start_port,
            issuer_agent.start_port + 1,
            genesis_data=issuer_agent.genesis_txns,
            genesis_txn_list=issuer_agent.genesis_txn_list,
            no_auto=issuer_agent.no_auto,
            tails_server_base_url=issuer_agent.tails_server_base_url,
            revocation=issuer_agent.revocation,
            timing=issuer_agent.show_timing,
            multitenant=issuer_agent.multitenant,
            mediation=issuer_agent.mediation,
            wallet_type=issuer_agent.wallet_type,
            seed=issuer_agent.seed,
            aip=issuer_agent.aip,
            cred_type=issuer_agent.cred_type,
            endorser_role=issuer_agent.endorser_role,
        )

        issuer_schema_name = "degree schema"
        issuer_schema_attrs = [
            "name",
            "date",
            "degree",
            "birthdate_dateint",
            "timestamp",
        ]
        if issuer_agent.cred_type == CRED_FORMAT_INDY:
            issuer_agent.public_did = True
            await issuer_agent.initialize(
                the_agent=agent,
                schema_name=issuer_schema_name,
                schema_attrs=issuer_schema_attrs,
                create_endorser_agent=(issuer_agent.endorser_role == "author")
                if issuer_agent.endorser_role
                else False,
            )
        elif issuer_agent.cred_type == CRED_FORMAT_JSON_LD:
            issuer_agent.public_did = True
            await issuer_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + issuer_agent.cred_type)

        # generate an invitation for Alice
        await issuer_agent.generate_invitation(
            display_qr=True, reuse_connections=issuer_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1a) Issue Credential tier1\n"
            "    (1b) Issue Credential tier2\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
        )
        if issuer_agent.revocation:
            options += "    (5) Revoke Credential\n" "    (6) Publish Revocations\n"
        options += "    (7) List connections\n"
        options += "    (8) List credentials\n"
        options += "    (9) List presentations\n"
        if issuer_agent.endorser_role and issuer_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if issuer_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[] ".format(
            "5/6/" if issuer_agent.revocation else "",
            "W/" if issuer_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and issuer_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await issuer_agent.agent.admin_POST(
                    f"/transactions/{issuer_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and issuer_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await issuer_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=issuer_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=issuer_agent.mediator_agent,
                        endorser_agent=issuer_agent.endorser_agent,
                        taa_accept=issuer_agent.taa_accept,
                    )
                else:
                    created = await issuer_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=issuer_agent.mediator_agent,
                        endorser_agent=issuer_agent.endorser_agent,
                        cred_type=issuer_agent.cred_type,
                        taa_accept=issuer_agent.taa_accept,
                    )
                # create a schema and cred def for the new wallet
                # TODO check first in case we are switching between existing wallets
                if created:
                    # TODO this fails because the new wallet doesn't get a public DID
                    await issuer_agent.create_schema_and_cred_def(
                        schema_name=issuer_schema_name,
                        schema_attrs=issuer_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1a":
                log_status("#13 Issue credential offer to tier1")

                connection_id = await issuer_agent.agent.get_connection_by_label("tier1.agent")

                if issuer_agent.aip == 20:
                    if issuer_agent.cred_type == CRED_FORMAT_JSON_LD:
                        offer_request = issuer_agent.agent.generate_credential_offer_tier1(
                            issuer_agent.aip,
                            issuer_agent.cred_type,
                            None,
                            exchange_tracing,
                            connection_id,
                        )

                    else:
                        raise Exception(
                            f"Error invalid credential type: {issuer_agent.cred_type}"
                        )

                    await issuer_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {issuer_agent.aip}")

            elif option == "1b":
                log_status("#13 Issue credential offer to tier2")

                connection_id = await issuer_agent.agent.get_connection_by_label("tier2.agent")

                if issuer_agent.aip == 20:
                    if issuer_agent.cred_type == CRED_FORMAT_JSON_LD:
                        offer_request = issuer_agent.agent.generate_credential_offer_tier2(
                            issuer_agent.aip,
                            issuer_agent.cred_type,
                            None,
                            exchange_tracing,
                            connection_id,
                        )

                    else:
                        raise Exception(
                            f"Error invalid credential type: {issuer_agent.cred_type}"
                        )

                    await issuer_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {issuer_agent.aip}")

            elif option == "3":
                msg = await prompt("Enter message: ")
                await issuer_agent.agent.admin_POST(
                    f"/connections/{issuer_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "4":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await issuer_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=issuer_agent.reuse_connections,
                    wait=True,
                )

            elif option == "5" and issuer_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                              await prompt("Publish now? [Y/N]: ", default="N")
                          ).strip() in "yY"
                try:
                    await issuer_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": issuer_agent.agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif option == "6" and issuer_agent.revocation:
                try:
                    resp = await issuer_agent.agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    issuer_agent.agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass

            elif option == "7":
                try:
                    await issuer_agent.agent.list_connections()
                except ClientError:
                    pass

            elif option == "8":
                try:
                    await issuer_agent.agent.list_w3c_credentials()
                except ClientError:
                    pass

            elif option == "9":
                try:
                    await issuer_agent.agent.list_presentations()
                except ClientError:
                    pass

        if issuer_agent.show_timing:
            timing = await issuer_agent.agent.fetch_timing()
            if timing:
                for line in issuer_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await issuer_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="issuer", port=8020)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "Issuer remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
