import argparse
import asyncio
import json
import jsonpath_ng
import jsonpath_ng.ext
import logging
import os
import random
import sys
import time
import yaml

from qrcode import QRCode

from aiohttp import ClientError

from runners.support.agent import (  # noqa:E402
    DemoAgent,
    default_genesis_txns,
    start_mediator_agent,
    connect_wallet_to_mediator,
    start_endorser_agent,
    connect_wallet_to_endorser,
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    DID_METHOD_KEY,
    KEY_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_json,
    log_msg,
    log_status,
    log_timer,
)

CRED_FORMAT_INDY = "indy"
CRED_FORMAT_JSON_LD = "json-ld"

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class AriesAgent(DemoAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        prefix: str = "Aries",
        no_auto: bool = False,
        seed: str = None,
        aip: int = 20,
        cred_type: str = CRED_FORMAT_INDY,
        endorser_role: str = None,
        revocation: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix=prefix,
            seed=seed,
            aip=aip,
            endorser_role=endorser_role,
            revocation=revocation,
            extra_args=(
                []
                if no_auto
                else [
                    "--auto-accept-invites",
                    "--auto-accept-requests",
                    "--auto-store-credential",
                ]
            ),
            **kwargs,
        )
        self.cred_type = cred_type
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # define a dict to hold credential attributes
        self.last_credential_received = None
        self.last_proof_received = None

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_oob_invitation(self, message):
        print("handle_oob_invitation()")
        pass

    async def handle_out_of_band(self, message):
        print("handle_out_of_band()")
        pass

    async def handle_connection_reuse(self, message):
        # we are reusing an existing connection, set our status to the existing connection
        if not self._connection_ready.done():
            self.connection_id = message["connection_id"]
            self.log("Connected")
            self._connection_ready.set_result(True)

    async def handle_connection_reuse_accepted(self, message):
        # we are reusing an existing connection, set our status to the existing connection
        if not self._connection_ready.done():
            self.connection_id = message["connection_id"]
            self.log("Connected")
            self._connection_ready.set_result(True)

    async def handle_connections(self, message):
        # a bit of a hack, but for the mediator connection self._connection_ready
        # will be None
        if not self._connection_ready:
            return
        conn_id = message["connection_id"]

        # inviter:
        if message.get("state") == "invitation":
            self.connection_id = conn_id

        # invitee:
        if (not self.connection_id) and message["rfc23_state"] == "invitation-received":
            self.connection_id = conn_id

        if conn_id == self.connection_id:
            # inviter or invitee:
            if message["rfc23_state"] in ["completed", "response-sent"]:
                if not self._connection_ready.done():
                    self.log("Connected")
                    self._connection_ready.set_result(True)

                # setup endorser properties
                self.log("Check for endorser role ...")
                if self.endorser_role:
                    if self.endorser_role == "author":
                        connection_job_role = "TRANSACTION_AUTHOR"
                        # short pause here to avoid race condition (both agents updating the connection role)
                        await asyncio.sleep(2.0)
                    elif self.endorser_role == "endorser":
                        connection_job_role = "TRANSACTION_ENDORSER"
                        # short pause here to avoid race condition (both agents updating the connection role)
                        await asyncio.sleep(1.0)
                    else:
                        connection_job_role = "None"

                    self.log(
                        f"Updating endorser role for connection: {self.connection_id}, {connection_job_role}"
                    )
                    await self.admin_POST(
                        "/transactions/" + self.connection_id + "/set-endorser-role",
                        params={"transaction_my_job": connection_job_role},
                    )

    async def handle_issue_credential(self, message):
        state = message.get("state")
        credential_exchange_id = message["credential_exchange_id"]
        prev_state = self.cred_state.get(credential_exchange_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[credential_exchange_id] = state

        self.log(
            "Credential: state = {}, credential_exchange_id = {}".format(
                state,
                credential_exchange_id,
            )
        )

        if state == "offer_received":
            log_status("#15 After receiving credential offer, send credential request")
            await self.admin_POST(
                f"/issue-credential/records/{credential_exchange_id}/send-request"
            )

        elif state == "credential_acked":
            cred_id = message["credential_id"]
            self.log(f"Stored credential {cred_id} in wallet")
            log_status(f"#18.1 Stored credential {cred_id} in wallet")
            resp = await self.admin_GET(f"/credential/{cred_id}")
            log_json(resp, label="Credential details:")
            log_json(
                message["credential_request_metadata"],
                label="Credential request metadata:",
            )
            self.log("credential_id", message["credential_id"])
            self.log("credential_definition_id", message["credential_definition_id"])
            self.log("schema_id", message["schema_id"])

        elif state == "request_received":
            log_status("#17 Issue credential to X")
            # issue credentials based on the credential_definition_id
            cred_attrs = self.cred_attrs[message["credential_definition_id"]]
            cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v} for (n, v) in cred_attrs.items()
                ],
            }
            try:
                cred_ex_rec = await self.admin_POST(
                    f"/issue-credential/records/{credential_exchange_id}/issue",
                    {
                        "comment": (
                            f"Issuing credential, exchange {credential_exchange_id}"
                        ),
                        "credential_preview": cred_preview,
                    },
                )
                rev_reg_id = cred_ex_rec.get("revoc_reg_id")
                cred_rev_id = cred_ex_rec.get("revocation_id")
                if rev_reg_id:
                    self.log(f"Revocation registry ID: {rev_reg_id}")
                if cred_rev_id:
                    self.log(f"Credential revocation ID: {cred_rev_id}")
            except ClientError:
                pass

        elif state == "abandoned":
            log_status("Credential exchange abandoned")
            self.log("Problem report message:", message.get("error_msg"))

    async def handle_issue_credential_v2_0(self, message):
        state = message.get("state")
        cred_ex_id = message["cred_ex_id"]
        prev_state = self.cred_state.get(cred_ex_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[cred_ex_id] = state

        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")

        if state == "request-received":
            log_status("#17 Issue credential to X")
            # issue credential based on offer preview in cred ex record
            await self.admin_POST(
                f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                {"comment": f"Issuing credential, exchange {cred_ex_id}"},
            )

        elif state == "offer-received":
            log_status("#15 After receiving credential offer, send credential request")
            if message["by_format"]["cred_offer"].get("indy"):
                await self.admin_POST(
                    f"/issue-credential-2.0/records/{cred_ex_id}/send-request"
                )
            elif message["by_format"]["cred_offer"].get("ld_proof"):
                holder_did = await self.admin_POST(
                    "/wallet/did/create",
                    {"method": "key", "options": {"key_type": "bls12381g2"}},
                )
                data = {"holder_did": holder_did["result"]["did"]}
                await self.admin_POST(
                    f"/issue-credential-2.0/records/{cred_ex_id}/send-request", data
                )

        elif state == "done":
            pass
            # Logic moved to detail record specific handler

        elif state == "abandoned":
            log_status("Credential exchange abandoned")
            self.log("Problem report message:", message.get("error_msg"))

    async def handle_issue_credential_v2_0_indy(self, message):
        rev_reg_id = message.get("rev_reg_id")
        cred_rev_id = message.get("cred_rev_id")
        cred_id_stored = message.get("cred_id_stored")

        if cred_id_stored:
            cred_id = message["cred_id_stored"]
            log_status(f"#18.1 Stored credential {cred_id} in wallet")
            cred = await self.admin_GET(f"/credential/{cred_id}")
            log_json(cred, label="Credential details:")
            self.log("credential_id", cred_id)
            self.log("cred_def_id", cred["cred_def_id"])
            self.log("schema_id", cred["schema_id"])
            # track last successfully received credential
            self.last_credential_received = cred

        if rev_reg_id and cred_rev_id:
            self.log(f"Revocation registry ID: {rev_reg_id}")
            self.log(f"Credential revocation ID: {cred_rev_id}")

    async def handle_issue_credential_v2_0_ld_proof(self, message):
        self.log(f"LD Credential: message = {message}")

    async def handle_issuer_cred_rev(self, message):
        pass

    async def handle_present_proof(self, message):
        state = message.get("state")

        presentation_exchange_id = message["presentation_exchange_id"]
        presentation_request = message["presentation_request"]
        self.log(
            "Presentation: state =",
            state,
            ", presentation_exchange_id =",
            presentation_exchange_id,
        )

        if state == "request_received":
            log_status(
                "#24 Query for credentials in the wallet that satisfy the proof request"
            )

            # include self-attested attributes (not included in credentials)
            credentials_by_reft = {}
            revealed = {}
            self_attested = {}
            predicates = {}

            try:
                # select credentials to provide for the proof
                credentials = await self.admin_GET(
                    f"/present-proof/records/{presentation_exchange_id}/credentials"
                )
                if credentials:
                    for row in sorted(
                        credentials,
                        key=lambda c: int(c["cred_info"]["attrs"]["timestamp"]),
                        reverse=True,
                    ):
                        for referent in row["presentation_referents"]:
                            if referent not in credentials_by_reft:
                                credentials_by_reft[referent] = row

                # submit the proof wit one unrevealed revealed attribute
                revealed_flag = False
                for referent in presentation_request["requested_attributes"]:
                    if referent in credentials_by_reft:
                        revealed[referent] = {
                            "cred_id": credentials_by_reft[referent]["cred_info"][
                                "referent"
                            ],
                            "revealed": revealed_flag,
                        }
                        revealed_flag = True
                    else:
                        self_attested[referent] = "my self-attested value"

                for referent in presentation_request["requested_predicates"]:
                    if referent in credentials_by_reft:
                        predicates[referent] = {
                            "cred_id": credentials_by_reft[referent]["cred_info"][
                                "referent"
                            ]
                        }

                log_status("#25 Generate the proof")
                request = {
                    "requested_predicates": predicates,
                    "requested_attributes": revealed,
                    "self_attested_attributes": self_attested,
                }

                log_status("#26 Send the proof to X")
                await self.admin_POST(
                    (
                        "/present-proof/records/"
                        f"{presentation_exchange_id}/send-presentation"
                    ),
                    request,
                )
            except ClientError:
                pass

        elif state == "presentation_received":
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof/records/{presentation_exchange_id}/verify-presentation"
            )
            self.log("Proof =", proof["verified"])

        elif state == "abandoned":
            log_status("Presentation exchange abandoned")
            self.log("Problem report message:", message.get("error_msg"))

    async def handle_present_proof_v2_0(self, message):
        state = message.get("state")
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "request-received":
            # prover role
            log_status(
                "#24 Query for credentials in the wallet that satisfy the proof request"
            )
            pres_request_indy = message["by_format"].get("pres_request", {}).get("indy")
            pres_request_dif = message["by_format"].get("pres_request", {}).get("dif")
            request = {}

            if not pres_request_dif and not pres_request_indy:
                raise Exception("Invalid presentation request received")

            if pres_request_indy:
                # include self-attested attributes (not included in credentials)
                creds_by_reft = {}
                revealed = {}
                self_attested = {}
                predicates = {}

                try:
                    # select credentials to provide for the proof
                    creds = await self.admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials"
                    )
                    if creds:
                        # select only indy credentials
                        creds = [x for x in creds if "cred_info" in x]
                        if "timestamp" in creds[0]["cred_info"]["attrs"]:
                            sorted_creds = sorted(
                                creds,
                                key=lambda c: int(c["cred_info"]["attrs"]["timestamp"]),
                                reverse=True,
                            )
                        else:
                            sorted_creds = creds
                        for row in sorted_creds:
                            for referent in row["presentation_referents"]:
                                if referent not in creds_by_reft:
                                    creds_by_reft[referent] = row

                    # submit the proof wit one unrevealed revealed attribute
                    revealed_flag = False
                    for referent in pres_request_indy["requested_attributes"]:
                        if referent in creds_by_reft:
                            revealed[referent] = {
                                "cred_id": creds_by_reft[referent]["cred_info"][
                                    "referent"
                                ],
                                "revealed": revealed_flag,
                            }
                            revealed_flag = True
                        else:
                            self_attested[referent] = "my self-attested value"

                    for referent in pres_request_indy["requested_predicates"]:
                        if referent in creds_by_reft:
                            predicates[referent] = {
                                "cred_id": creds_by_reft[referent]["cred_info"][
                                    "referent"
                                ]
                            }

                    log_status("#25 Generate the indy proof")
                    indy_request = {
                        "indy": {
                            "requested_predicates": predicates,
                            "requested_attributes": revealed,
                            "self_attested_attributes": self_attested,
                        }
                    }
                    request.update(indy_request)
                except ClientError:
                    pass

            if pres_request_dif:
                try:
                    # select credentials to provide for the proof
                    creds = await self.admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials"
                    )
                    if creds and 0 < len(creds):
                        # select only dif credentials
                        creds = [x for x in creds if "issuanceDate" in x]
                        creds = sorted(
                            creds,
                            key=lambda c: c["issuanceDate"],
                            reverse=True,
                        )
                        records = creds
                    else:
                        records = []

                    log_status("#25 Generate the dif proof")
                    dif_request = {
                        "dif": {},
                    }
                    # specify the record id for each input_descriptor id:
                    dif_request["dif"]["record_ids"] = {}
                    for input_descriptor in pres_request_dif["presentation_definition"][
                        "input_descriptors"
                    ]:
                        input_descriptor_schema_uri = []
                        for element in input_descriptor["schema"]:
                            input_descriptor_schema_uri.append(element["uri"])

                        for record in records:
                            if self.check_input_descriptor_record_id(
                                input_descriptor_schema_uri, record
                            ):
                                record_id = record["record_id"]
                                dif_request["dif"]["record_ids"][
                                    input_descriptor["id"]
                                ] = [
                                    record_id,
                                ]
                                break
                    log_msg("presenting ld-presentation:", dif_request)
                    request.update(dif_request)

                    # NOTE that the holder/prover can also/or specify constraints by including the whole proof request
                    # and constraining the presented credentials by adding filters, for example:
                    #
                    # request = {
                    #     "dif": pres_request_dif,
                    # }
                    # request["dif"]["presentation_definition"]["input_descriptors"]["constraints"]["fields"].append(
                    #      {
                    #          "path": [
                    #              "$.id"
                    #          ],
                    #          "purpose": "Specify the id of the credential to present",
                    #          "filter": {
                    #              "const": "https://credential.example.com/residents/1234567890"
                    #          }
                    #      }
                    # )
                    #
                    # (NOTE the above assumes the credential contains an "id", which is an optional field)

                except ClientError:
                    pass

            log_status("#26 Send the proof to X: " + json.dumps(request))
            await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/send-presentation",
                request,
            )

        elif state == "presentation-received":
            # verifier role
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )
            self.log("Proof =", proof["verified"])
            self.last_proof_received = proof

        elif state == "abandoned":
            log_status("Presentation exchange abandoned")
            self.log("Problem report message:", message.get("error_msg"))

    async def handle_basicmessages(self, message):
        self.log("Received message:", message["content"])

    async def handle_endorse_transaction(self, message):
        self.log("Received transaction message:", message.get("state"))

    async def handle_revocation_notification(self, message):
        self.log("Received revocation notification message:", message)

    async def generate_invitation(
        self,
        use_did_exchange: bool,
        auto_accept: bool = True,
        display_qr: bool = False,
        reuse_connections: bool = False,
        wait: bool = False,
    ):
        self._connection_ready = asyncio.Future()
        with log_timer("Generate invitation duration:"):
            # Generate an invitation
            log_status(
                "#7 Create a connection to alice and print out the invite details"
            )
            invi_rec = await self.get_invite(
                use_did_exchange,
                auto_accept=auto_accept,
                reuse_connections=reuse_connections,
            )

        if display_qr:
            qr = QRCode(border=1)
            qr.add_data(invi_rec["invitation_url"])
            log_msg(
                "Use the following JSON to accept the invite from another demo agent."
                " Or use the QR code to connect from a mobile agent."
            )
            log_msg(
                json.dumps(invi_rec["invitation"]), label="Invitation Data:", color=None
            )
            qr.print_ascii(invert=True)

        if wait:
            log_msg("Waiting for connection...")
            await self.detect_connection()

        return invi_rec

    async def input_invitation(self, invite_details: dict, wait: bool = False):
        self._connection_ready = asyncio.Future()
        with log_timer("Connect duration:"):
            connection = await self.receive_invite(invite_details)
            log_json(connection, label="Invitation response:")

        if wait:
            log_msg("Waiting for connection...")
            await self.detect_connection()

    async def create_schema_and_cred_def(
        self, schema_name, schema_attrs, revocation, version=None
    ):
        with log_timer("Publish schema/cred def duration:"):
            log_status("#3/4 Create a new schema/cred def on the ledger")
            if not version:
                version = format(
                    "%d.%d.%d"
                    % (
                        random.randint(1, 101),
                        random.randint(1, 101),
                        random.randint(1, 101),
                    )
                )
            (
                _,
                cred_def_id,
            ) = await self.register_schema_and_creddef(  # schema id
                schema_name,
                version,
                schema_attrs,
                support_revocation=revocation,
                revocation_registry_size=TAILS_FILE_COUNT if revocation else None,
            )
            return cred_def_id

    def check_input_descriptor_record_id(
        self, input_descriptor_schema_uri, record
    ) -> bool:
        result = False
        for uri in input_descriptor_schema_uri:
            for record_type in record["type"]:
                if record_type in uri:
                    result = True
                    break
                result = False

        return result

    async def list_connections(self):
        connections = await self.admin_GET(
            "/connections"
        )

        log_json(connections)

    async def list_w3c_credentials(self):
        credentials = await self.admin_POST(
            "/credentials/w3c", {}
        )

        log_json(credentials)

    async def list_presentations(self):
        presentations = await self.admin_GET(
            "/present-proof-2.0/records", {}
        )

        log_json(presentations)

    async def get_connection_by_label(self, label):
        connections = await self.admin_GET(
            "/connections"
        )

        jsonpath_expr = jsonpath_ng.ext.parse(f"$.results[?(@.their_label == '{label}')].connection_id")
        result = jsonpath_expr.find(connections)
        return [match.value for match in result][0]

