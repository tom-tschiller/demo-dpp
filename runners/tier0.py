import asyncio
import base64
import binascii
import datetime
import json
import logging
import os
import sys
import time
from urllib.parse import urlparse
from qrcode import QRCode

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
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

SELF_ATTESTED = os.getenv("SELF_ATTESTED")

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class Tier0Agent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        aip: int = 20,
        endorser_role: str = None,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Tier0",
            no_auto=no_auto,
            seed=None,
            aip=aip,
            endorser_role=endorser_role,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()


    def generate_proof_request_web_request(
        self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        age = 18
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
        if aip == 10:
            req_attrs = [
                {
                    "name": "name",
                    "restrictions": [{"schema_name": "degree schema"}],
                },
                {
                    "name": "date",
                    "restrictions": [{"schema_name": "degree schema"}],
                },
            ]
            if revocation:
                req_attrs.append(
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "degree schema"}],
                        "non_revoked": {"to": int(time.time() - 1)},
                    },
                )
            else:
                req_attrs.append(
                    {
                        "name": "degree",
                        "restrictions": [{"schema_name": "degree schema"}],
                    }
                )
            if SELF_ATTESTED:
                # test self-attested claims
                req_attrs.append(
                    {"name": "self_attested_thing"},
                )
            req_preds = [
                # test zero-knowledge proofs
                {
                    "name": "birthdate_dateint",
                    "p_type": "<=",
                    "p_value": int(birth_date.strftime(birth_date_format)),
                    "restrictions": [{"schema_name": "degree schema"}],
                }
            ]
            indy_proof_request = {
                "name": "Proof of Education",
                "version": "1.0",
                "requested_attributes": {
                    f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                },
                "requested_predicates": {
                    f"0_{req_pred['name']}_GE_uuid": req_pred for req_pred in req_preds
                },
            }

            if revocation:
                indy_proof_request["non_revoked"] = {"to": int(time.time())}

            proof_request_web_request = {
                "proof_request": indy_proof_request,
                "trace": exchange_tracing,
            }
            if not connectionless:
                proof_request_web_request["connection_id"] = self.connection_id
            return proof_request_web_request

        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                req_attrs = [
                    {
                        "name": "name",
                        "restrictions": [{"schema_name": "degree schema"}],
                    },
                    {
                        "name": "date",
                        "restrictions": [{"schema_name": "degree schema"}],
                    },
                ]
                if revocation:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"schema_name": "degree schema"}],
                            "non_revoked": {"to": int(time.time() - 1)},
                        },
                    )
                else:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"schema_name": "degree schema"}],
                        }
                    )
                if SELF_ATTESTED:
                    # test self-attested claims
                    req_attrs.append(
                        {"name": "self_attested_thing"},
                    )
                req_preds = [
                    # test zero-knowledge proofs
                    {
                        "name": "birthdate_dateint",
                        "p_type": "<=",
                        "p_value": int(birth_date.strftime(birth_date_format)),
                        "restrictions": [{"schema_name": "degree schema"}],
                    }
                ]
                indy_proof_request = {
                    "name": "Proof of Education",
                    "version": "1.0",
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                    },
                    "requested_predicates": {
                        f"0_{req_pred['name']}_GE_uuid": req_pred
                        for req_pred in req_preds
                    },
                }

                if revocation:
                    indy_proof_request["non_revoked"] = {"to": int(time.time())}

                proof_request_web_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                proof_request_web_request = {
                    "comment": "test proof request for json-ld",
                    "presentation_request": {
                        "dif": {
                            "options": {
                                "challenge": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
                                "domain": "4jt78h47fh47",
                            },
                            "presentation_definition": {
                                "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
                                "format": {"ldp_vp": {"proof_type": [SIG_TYPE_BLS]}},
                                "input_descriptors": [
                                    {
                                        "id": "citizenship_input_1",
                                        "name": "EU Driver's License",
                                        "schema": [
                                            {
                                                "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
                                            },
                                            {
                                                "uri": "https://w3id.org/citizenship#PermanentResident"
                                            },
                                        ],
                                        "constraints": {
                                            "limit_disclosure": "required",
                                            "is_holder": [
                                                {
                                                    "directive": "required",
                                                    "field_id": [
                                                        "1f44d55f-f161-4938-a659-f8026467f126"
                                                    ],
                                                }
                                            ],
                                            "fields": [
                                                {
                                                    "id": "1f44d55f-f161-4938-a659-f8026467f126",
                                                    "path": [
                                                        "$.credentialSubject.familyName"
                                                    ],
                                                    "purpose": "The claim must be from one of the specified person",
                                                    "filter": {"const": "SMITH"},
                                                },
                                                {
                                                    "path": [
                                                        "$.credentialSubject.givenName"
                                                    ],
                                                    "purpose": "The claim must be from one of the specified person",
                                                },
                                            ],
                                        },
                                    }
                                ],
                            },
                        }
                    },
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")


async def input_invitation(agent_container):
    agent_container.agent._connection_ready = asyncio.Future()
    async for details in prompt_loop("Invite details: "):
        b64_invite = None
        try:
            url = urlparse(details)
            query = url.query
            if query and "c_i=" in query:
                pos = query.index("c_i=") + 4
                b64_invite = query[pos:]
            elif query and "oob=" in query:
                pos = query.index("oob=") + 4
                b64_invite = query[pos:]
            else:
                b64_invite = details
        except ValueError:
            b64_invite = details

        if b64_invite:
            try:
                padlen = 4 - len(b64_invite) % 4
                if padlen <= 2:
                    b64_invite += "=" * padlen
                invite_json = base64.urlsafe_b64decode(b64_invite)
                details = invite_json.decode("utf-8")
            except binascii.Error:
                pass
            except UnicodeDecodeError:
                pass

        if details:
            try:
                details = json.loads(details)
                break
            except json.JSONDecodeError as e:
                log_msg("Invalid invitation:", str(e))

    with log_timer("Connect duration:"):
        connection = await agent_container.input_invitation(details, wait=True)


async def main(args):
    tier0_agent = await create_agent_with_args(args, ident="tier0")

    try:
        log_status(
            "#7 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {tier0_agent.wallet_type})"
                if tier0_agent.wallet_type
                else ""
            )
        )
        agent = Tier0Agent(
            "tier0.agent",
            tier0_agent.start_port,
            tier0_agent.start_port + 1,
            genesis_data=tier0_agent.genesis_txns,
            genesis_txn_list=tier0_agent.genesis_txn_list,
            no_auto=tier0_agent.no_auto,
            tails_server_base_url=tier0_agent.tails_server_base_url,
            revocation=tier0_agent.revocation,
            timing=tier0_agent.show_timing,
            multitenant=tier0_agent.multitenant,
            mediation=tier0_agent.mediation,
            wallet_type=tier0_agent.wallet_type,
            aip=tier0_agent.aip,
            endorser_role=tier0_agent.endorser_role,
        )

        await tier0_agent.initialize(the_agent=agent)

        # log_status("#9 Input faber.py invitation details")
        # await input_invitation(tier0_agent)

        exchange_tracing = False
        options = (
            "    (2) Send Proof Request\n"
            "    (2a) Send *Connectionless* Proof Request (requires a Mobile client)\n"
            "    (3) Send Message\n"
            "    (4) Input New Invitation\n"
            "    (4a) Create New Invitation\n"
        )
        if tier0_agent.endorser_role and tier0_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if tier0_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (X) Exit?\n[2/2a/3/4/4a/{}X] ".format(
            "W/" if tier0_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and tier0_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await tier0_agent.agent.admin_POST(
                    f"/transactions/{tier0_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did, "endorser_name": "endorser"},
                )

            elif option in "wW" and tier0_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    await tier0_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=tier0_agent.agent.get_new_webhook_port(),
                        mediator_agent=tier0_agent.mediator_agent,
                        taa_accept=tier0_agent.taa_accept,
                    )
                else:
                    await tier0_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        mediator_agent=tier0_agent.mediator_agent,
                        taa_accept=tier0_agent.taa_accept,
                    )

            elif option == "2":
                log_status("#20 Request proof of degree from alice")
                if tier0_agent.aip == 10:
                    proof_request_web_request = (
                        tier0_agent.agent.generate_proof_request_web_request(
                            tier0_agent.aip,
                            tier0_agent.cred_type,
                            tier0_agent.revocation,
                            exchange_tracing,
                        )
                    )
                    await tier0_agent.agent.admin_POST(
                        "/present-proof/send-request", proof_request_web_request
                    )
                    pass

                elif tier0_agent.aip == 20:
                    if tier0_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            tier0_agent.agent.generate_proof_request_web_request(
                                tier0_agent.aip,
                                tier0_agent.cred_type,
                                tier0_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    elif tier0_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            tier0_agent.agent.generate_proof_request_web_request(
                                tier0_agent.aip,
                                tier0_agent.cred_type,
                                tier0_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    else:
                        raise Exception(
                            "Error invalid credential type:" + tier0_agent.cred_type
                        )

                    await agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {tier0_agent.aip}")

            elif option == "2a":
                log_status("#20 Request * Connectionless * proof of degree from alice")
                if tier0_agent.aip == 10:
                    proof_request_web_request = (
                        tier0_agent.agent.generate_proof_request_web_request(
                            tier0_agent.aip,
                            tier0_agent.cred_type,
                            tier0_agent.revocation,
                            exchange_tracing,
                            connectionless=True,
                        )
                    )
                    proof_request = await tier0_agent.agent.admin_POST(
                        "/present-proof/create-request", proof_request_web_request
                    )
                    pres_req_id = proof_request["presentation_exchange_id"]
                    url = (
                        os.getenv("WEBHOOK_TARGET")
                        or (
                            "http://"
                            + os.getenv("DOCKERHOST").replace(
                                "{PORT}", str(tier0_agent.agent.admin_port + 1)
                            )
                            + "/webhooks"
                        )
                    ) + f"/pres_req/{pres_req_id}/"
                    log_msg(f"Proof request url: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg(
                        "Scan the following QR code to accept the proof request from a mobile agent."
                    )
                    qr.print_ascii(invert=True)

                elif tier0_agent.aip == 20:
                    if tier0_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            tier0_agent.agent.generate_proof_request_web_request(
                                tier0_agent.aip,
                                tier0_agent.cred_type,
                                tier0_agent.revocation,
                                exchange_tracing,
                                connectionless=True,
                            )
                        )
                    elif tier0_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            tier0_agent.agent.generate_proof_request_web_request(
                                tier0_agent.aip,
                                tier0_agent.cred_type,
                                tier0_agent.revocation,
                                exchange_tracing,
                                connectionless=True,
                            )
                        )
                    else:
                        raise Exception(
                            "Error invalid credential type:" + tier0_agent.cred_type
                        )

                    proof_request = await tier0_agent.agent.admin_POST(
                        "/present-proof-2.0/create-request", proof_request_web_request
                    )
                    pres_req_id = proof_request["pres_ex_id"]
                    url = (
                        "http://"
                        + os.getenv("DOCKERHOST").replace(
                            "{PORT}", str(tier0_agent.agent.admin_port + 1)
                        )
                        + "/webhooks/pres_req/"
                        + pres_req_id
                        + "/"
                    )
                    log_msg(f"Proof request url: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg(
                        "Scan the following QR code to accept the proof request from a mobile agent."
                    )
                    qr.print_ascii(invert=True)
                else:
                    raise Exception(f"Error invalid AIP level: {tier0_agent.aip}")

            elif option == "3":
                msg = await prompt("Enter message: ")
                if msg:
                    await tier0_agent.agent.admin_POST(
                        f"/connections/{tier0_agent.agent.connection_id}/send-message",
                        {"content": msg},
                    )

            elif option == "4":
                # handle new invitation
                log_status("Input new invitation details")
                await input_invitation(tier0_agent)

            elif option == "4a":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await tier0_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=tier0_agent.reuse_connections,
                    wait=True,
                )


        if tier0_agent.show_timing:
            timing = await tier0_agent.agent.fetch_timing()
            if timing:
                for line in tier0_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await tier0_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="tier0", port=8060)
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
                "Tier0 remote debugging to "
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

    check_requires(args)

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
