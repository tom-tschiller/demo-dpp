import asyncio
import base64
import binascii
import datetime
import json
import jsonpath_ng
import jsonpath_ng.ext
import logging
import os
import sys
import uuid
from urllib.parse import urlparse
from qrcode import QRCode

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
        cred_type: str = "",
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
            cred_type=cred_type,
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

    async def handle_basicmessages(self, message):
        await super().handle_basicmessages(message)
        try:
            raise Exception('error')
        except Exception as error:
            log_msg('catch error' + repr(error))
    async def handle_present_proof_v2_0(self, message):
        await super().handle_present_proof_v2_0(message)
        state = message.get("state")
        pres_ex_id = message["pres_ex_id"]

        try:

            if state == "presentation-received":
                jsonpath_expr = jsonpath_ng.ext.parse(
                    f"$.by_format.pres.dif.verifiableCredential[0].credentialSubject.previousTiers")
                result = jsonpath_expr.find(message)
                test = [match.value for match in result][0]

                for previousTier in test['itemListElement']:
                    result = jsonpath_ng.ext.parse(f"$.item.id").find(previousTier)
                    product_id = [match.value for match in result][0]

                    result = jsonpath_ng.ext.parse(f"$.item.holder.name").find(previousTier)
                    holder_name = [match.value for match in result][0]

                    log_msg(f"Previours tier product_id: {product_id} / holder_name {holder_name}")

                    connection_id = await self.get_connection_by_label(f"{holder_name}.agent")

                    log_msg(f"Connection for tier2: {connection_id}")
                    proof_request_web_request = (
                        self.generate_proof_request_web_request_by_id(
                            self.aip,
                            self.cred_type,
                            self.revocation,
                            None,
                            connection_id,
                            product_id
                        )
                    )
                    await self.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

        except Exception as error:
            log_msg('catch error' + repr(error))



    def generate_proof_request_web_request(
        self, aip, cred_type, revocation, exchange_tracing, connection_id
    ):
        challenge_id = str(uuid.uuid4())
        presentation_id = str(uuid.uuid4())

        if aip == 20:
            if cred_type == CRED_FORMAT_JSON_LD:
                proof_request_web_request = {
                    "comment": "test proof request for json-ld",
                    "connection_id": connection_id,
                    "presentation_request": {
                        "dif": {
                            "options": {
                                "challenge": challenge_id,
                                "domain": "4jt78h47fh47",
                            },
                            "presentation_definition": {
                                "id": presentation_id,
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
                                            "fields": [
                                                {
                                                    "path": [
                                                        "$.credentialSubject.serialNumber"
                                                    ],
                                                    "filter": {"const": "111"},
                                                },
                                                {
                                                    "path": [
                                                        "$.credentialSubject.co2"
                                                    ],
                                                },
                                                {
                                                    "path": [
                                                        "$.credentialSubject.previousTiers"
                                                    ],
                                                },
                                            ],
                                        },
                                    }
                                ],
                            },
                        }
                    },
                }

                return proof_request_web_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_proof_request_web_request_by_id(
        self, aip, cred_type, revocation, exchange_tracing, connection_id, product_id
    ):
        challenge_id = str(uuid.uuid4())
        presentation_id = str(uuid.uuid4())

        if aip == 20:
            if cred_type == CRED_FORMAT_JSON_LD:
                proof_request_web_request = {
                    "comment": "test proof request for json-ld",
                    "connection_id": connection_id,
                    "presentation_request": {
                        "dif": {
                            "options": {
                                "challenge": challenge_id,
                                "domain": "4jt78h47fh47",
                            },
                            "presentation_definition": {
                                "id": presentation_id,
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
                                            "fields": [
                                                {
                                                    "path": [
                                                        "$.id"
                                                    ],
                                                    "filter": {"const": product_id},
                                                },
                                                {
                                                    "path": [
                                                        "$.credentialSubject.co2"
                                                    ],
                                                },
                                                {
                                                    "path": [
                                                        "$.credentialSubject.previousTiers"
                                                    ],
                                                },
                                            ],
                                        },
                                    }
                                ],
                            },
                        }
                    },
                }

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
            cred_type=tier0_agent.cred_type,
            endorser_role=tier0_agent.endorser_role,
        )

        await tier0_agent.initialize(the_agent=agent)

        # generate an invitation for Alice
        await tier0_agent.generate_invitation(
            display_qr=True, reuse_connections=tier0_agent.reuse_connections, wait=True
        )

        log_msg(f"agent: {tier0_agent.agent}")

        exchange_tracing = False
        options = (
            "    (2) Send Proof Request (tier1)\n"
            "    (2a) Send Proof Request (tier2)\n"
            "    (3) Send Message\n"
            "    (4) Input New Invitation\n"
            "    (4a) Create New Invitation\n"
            "    (7) List connections\n"
            "    (8) List credentials\n"
            "    (9) List presentations\n"
        )
        if tier0_agent.endorser_role and tier0_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if tier0_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (X) Exit?\n[] ".format(
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
                log_status("#20 Request proof of degree from tier1")

                if tier0_agent.aip == 20:
                    connection_id = await tier0_agent.agent.get_connection_by_label("tier1.agent")

                    if tier0_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            tier0_agent.agent.generate_proof_request_web_request(
                                tier0_agent.aip,
                                tier0_agent.cred_type,
                                tier0_agent.revocation,
                                exchange_tracing,
                                connection_id,
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
                log_status("#20 Request proof of degree from tier2")

                if tier0_agent.aip == 20:
                    connection_id = await tier0_agent.agent.get_connection_by_label("tier2.agent")

                    if tier0_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            tier0_agent.agent.generate_proof_request_web_request_by_id(
                                tier0_agent.aip,
                                tier0_agent.cred_type,
                                tier0_agent.revocation,
                                exchange_tracing,
                                connection_id,
                                "https://credential.example.com/product/2"
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

            elif option == "7":
                try:
                    await tier0_agent.agent.list_connections()
                except ClientError:
                    pass

            elif option == "8":
                try:
                    await tier0_agent.agent.list_w3c_credentials()
                except ClientError:
                    pass

            elif option == "9":
                try:
                    await tier0_agent.agent.list_presentations()
                except ClientError:
                    pass

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
