import asyncio
import base64
import binascii
import json
import logging
import os
import sys
from urllib.parse import urlparse

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
    SIG_TYPE_ED25519,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class Tier2Agent(AriesAgent):
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
            prefix="Tier2",
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

    def send_credential_request_tier2(self, aip, cred_type, issuer_did, connection_id):

        if aip == 20:
            if cred_type == CRED_FORMAT_JSON_LD:
                holder_did = f"did:sov:{self.did}"
                # issuer_did = "did:sov:EivNVN4M2YXJ94Q7uCxxdx"
                offer_request = {
                    "connection_id": connection_id,
                    "holder_did": holder_did,
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
                                "issuer": issuer_did,
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
    tier2_agent = await create_agent_with_args(args, ident="tier2")

    try:
        log_status(
            "#7 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {tier2_agent.wallet_type})"
                if tier2_agent.wallet_type
                else ""
            )
        )
        agent = Tier2Agent(
            "tier2.agent",
            tier2_agent.start_port,
            tier2_agent.start_port + 1,
            genesis_data=tier2_agent.genesis_txns,
            genesis_txn_list=tier2_agent.genesis_txn_list,
            no_auto=tier2_agent.no_auto,
            tails_server_base_url=tier2_agent.tails_server_base_url,
            revocation=tier2_agent.revocation,
            timing=tier2_agent.show_timing,
            multitenant=tier2_agent.multitenant,
            mediation=tier2_agent.mediation,
            wallet_type=tier2_agent.wallet_type,
            aip=tier2_agent.aip,
            cred_type=tier2_agent.cred_type,
            endorser_role=tier2_agent.endorser_role,
        )

        await tier2_agent.initialize(the_agent=agent)

        log_status("#9 Input faber.py invitation details")
        await input_invitation(tier2_agent)

        options = (
            "    (1) Send Credential Request\n"
            "    (3) Send Message\n"
            "    (4) Input New Invitation\n"
            "    (7) List connections\n"
            "    (7a) List DIDs\n"
            "    (8) List credentials\n"
            "    (9) List presentations\n"
        )
        if tier2_agent.endorser_role and tier2_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if tier2_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (X) Exit?\n[] ".format(
            "W/" if tier2_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and tier2_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await tier2_agent.agent.admin_POST(
                    f"/transactions/{tier2_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did, "endorser_name": "endorser"},
                )

            elif option in "wW" and tier2_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    await tier2_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=tier2_agent.agent.get_new_webhook_port(),
                        mediator_agent=tier2_agent.mediator_agent,
                        taa_accept=tier2_agent.taa_accept,
                    )
                else:
                    await tier2_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        mediator_agent=tier2_agent.mediator_agent,
                        taa_accept=tier2_agent.taa_accept,
                    )

            elif option == "1":
                log_status("Request credential from issuer")

                connection_id = await tier2_agent.agent.get_connection_by_label("issuer.agent")

                issuer_did = await prompt("Issuer DID: ")

                if tier2_agent.aip == 20:
                    if tier2_agent.cred_type == CRED_FORMAT_JSON_LD:
                        offer_request = tier2_agent.agent.send_credential_request_tier2(
                            tier2_agent.aip,
                            tier2_agent.cred_type,
                            issuer_did,
                            connection_id,
                        )

                    else:
                        raise Exception(
                            f"Error invalid credential type: {tier2_agent.cred_type}"
                        )

                    await tier2_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-request", offer_request
                    )

            elif option == "3":
                msg = await prompt("Enter message: ")
                if msg:
                    await tier2_agent.agent.admin_POST(
                        f"/connections/{tier2_agent.agent.connection_id}/send-message",
                        {"content": msg},
                    )

            elif option == "4":
                # handle new invitation
                log_status("Input new invitation details")
                await input_invitation(tier2_agent)

            elif option == "7":
                try:
                    await tier2_agent.agent.list_connections()
                except ClientError:
                    pass

            elif option == "7a":
                try:
                    await tier2_agent.agent.list_dids()
                except ClientError:
                    pass

            elif option == "8":
                try:
                    await tier2_agent.agent.list_w3c_credentials()
                except ClientError:
                    pass

            elif option == "9":
                try:
                    await tier2_agent.agent.list_presentations()
                except ClientError:
                    pass

        if tier2_agent.show_timing:
            timing = await tier2_agent.agent.fetch_timing()
            if timing:
                for line in tier2_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await tier2_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="tier2", port=8080)
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
                "Tier2 remote debugging to "
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
