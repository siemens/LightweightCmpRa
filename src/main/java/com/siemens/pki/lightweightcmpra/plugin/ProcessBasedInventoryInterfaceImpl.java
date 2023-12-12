package com.siemens.pki.lightweightcmpra.plugin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;

import java.io.*;
import java.util.Base64;

public class ProcessBasedInventoryInterfaceImpl implements InventoryInterface {

    private ObjectNode formJson(byte[] transactionID, String requesterDn, byte[] certTemplate,
                                String requestedSubjectDn, byte[] pkiMessage) {

        ObjectMapper objectMapper = new ObjectMapper();

        ObjectNode root = objectMapper.createObjectNode();

        // Create the "subject" object
        // TODO check the actual structure of requestedSubjectDn
        ObjectNode subject = objectMapper.createObjectNode();
        subject.put("common_name",  requestedSubjectDn);

//        ArrayNode names = objectMapper.createArrayNode();
//        names.add("prefetch.net");
//        subject.set("names", names);

        // Add "subject" object to the root
        root.set("subject", subject);

        // Add other fields
        //root.put("sigalg", "SHA256WithRSA");
        root.put("transaction_id", transactionID);
        root.put("requesterDN", requesterDn);

        return root;
        /* Create Json from requesterDN and transactionID
         *
         * {
         *   "subject": {
         *       "common_name": "prefetch.net",
         *       "names": [
         *       "prefetch.net"
         *       ]
         *   },
         *   "sigalg": "SHA256WithRSA",
         *   "transaction_id": "B9:1A:41:B8:64:AE:D7:62:16:B7:27:5E:3B:FE:36:C9:8E:7D:2B:35"
         *   }
         *
         */
    }

    /**
     * check and optionally modify a CRMF certificate request that was received in a
     * CMP ir, cr or kur message.
     *
     * @param transactionID      the transactionID of the CMP request message. The
     *                           transactionID can be used to correlate calls of
     *                           {@link #checkAndModifyCertRequest(byte[], String, byte[], String, byte[])}
     *                           and
     *                           {@link #learnEnrollmentResult(byte[], byte[], String, String, String)}.
     * @param requesterDn        Distinguished Name (DN) of the CMP requester. This
     *                           is the subject of the first certificate in the
     *                           extraCerts field of the CMP request or the sender
     *                           extracted from the PKI message header. If neither
     *                           signature-based protection was used nor the sender
     *                           field was set the requesterDn is <code>null</code>.
     *                           The DN is an X500 name formatted as string
     *                           according to the BouncyCastle library defaults.
     * @param certTemplate       the ASN.1 DER-encoded CertTemplate of the
     *                           certificate request as received from the requester.
     *                           Note that it may indicate central key generation,
     *                           optionally specifying key parameters.
     * @param requestedSubjectDn subject DN extracted from the CertTemplate of the
     *                           request or <code>null</code> if subject was not
     *                           present. The DN is an X500 name formatted as string
     *                           according to the BouncyCastle library defaults.
     *                           This parameter is provided for convenience.
     * @param pkiMessage         the ASN.1 DER-encoded CMP ir, cr or kur message
     * @return result of validation check
     */
    @Override
    public CheckAndModifyResult checkAndModifyCertRequest(byte[] transactionID, String requesterDn, byte[] certTemplate, String requestedSubjectDn, byte[] pkiMessage) {
        /* 1. form Json
         * 2. stringify json
         * 3. base64-encode pkimessage
         * 3. form wrapped requestÄ (JSON \r\n\r\n pkimessage in base64) --> attach separator and pkimessage to json-string
         * 4. call process and put the stuff from §3 into its stdout
         * 5. wait for it to returnü capture status code and stdout
         * 6. react to the data you received ##TEST return true
         */
        // Form Json
        ObjectNode json = formJson(transactionID, requesterDn, certTemplate, requestedSubjectDn, pkiMessage);

        // Stringify json
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonString;

        try {
            jsonString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        } catch (JsonProcessingException ex) {
            ex.printStackTrace();
            return new CheckAndModifyResult() {
                @Override
                public byte[] getUpdatedCertTemplate() {
                    return null;
                }
                @Override
                public boolean isGranted() {
                    return false;
                }
            };
        }

        // Encode pkimessage in base64
        String encodedPkiMessage = Base64.getEncoder().encodeToString(pkiMessage);

        // Wrapped request
        String request = jsonString + "\r\n\r\n" + encodedPkiMessage;

        try {
            // Start external process with parameters
            Process process = new ProcessBuilder("C:\\Users\\z004thmt\\Code\\raplugin-csharp\\bin\\Debug\\net6.0-windows\\RaPluginDummy.exe").start();

            // Get input and output stream of external process
            BufferedReader procInput = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            OutputStream procOutput = process.getOutputStream();

            // Send input to the process
            procOutput.write(request.getBytes());
            procOutput.close();

            // Wait for the process to finish, but not more than 30 seconds
            boolean finished = process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);

            final String processResult;
            final int processStatus;

            // If the process finished, capture its output and status code
            if (finished) {
                processStatus = process.exitValue();

                // Read the process output
                StringBuilder outputBuilder = new StringBuilder();
                String line;
                while ((line = procInput.readLine()) != null) {
                    outputBuilder.append(line);
                }
                processResult = outputBuilder.toString();
            } else {
                // Handle case where the process didn't finish within 30 seconds
                processStatus = -1;
                processResult = "";
                System.err.println("Process didn't finish within 30 seconds.");
            }

            return new CheckAndModifyResult() {

                @Override
                public byte[] getUpdatedCertTemplate() {
                    return null;
                }

                @Override
                public boolean isGranted() {
                    return (processStatus == 0 && processResult.equals("1"));
                }

            };
        } catch (IOException | InterruptedException ex) {
            ex.printStackTrace();
            return new CheckAndModifyResult() {

                @Override
                public byte[] getUpdatedCertTemplate() {
                    return null;
                }

                @Override
                public boolean isGranted() {
                    return false;
                }

            };
        }
    }

    /**
     * check PKCS#10 certificate request that was received in CMP p10cr message. Note
     * that such certificate request cannot be modified because it is self-signed by
     * the requester.
     *
     * @param transactionID      the transactionID of the CMP request message. The
     *                           transactionID can be used to correlate calls of
     *                           {@link #checkP10CertRequest(byte[], String, byte[], String, byte[])}
     *                           and
     *                           {@link #learnEnrollmentResult(byte[], byte[], String, String, String)}.
     * @param requesterDn        Distinguished Name (DN) of the CMP requester. This
     *                           is the subject of the first certificate in the
     *                           extraCerts field of the CMP request or the sender
     *                           extracted from the PKI message header. If neither
     *                           signature-based protection was used nor the sender
     *                           field was set the requesterDn is <code>null</code>.
     *                           The DN is an X500 name formatted as string
     *                           according to the BouncyCastle library defaults.
     * @param pkcs10CertRequest  the ASN.1 DER-encoded PKCS#10 certificate request
     *                           as received from a requester in a p10cr request.
     * @param requestedSubjectDn subject DN extracted from the
     *                           CertificationRequestInfo of the pkcs10CertRequest.
     *                           The DN is an X500 name formatted as string
     *                           according to the BouncyCastle library defaults.
     *                           This parameter is provided for convenience.
     * @param pkiMessage         the ASN.1 DER-encoded CMP p10cr message
     * @return <code>true</code> if the request is granted.
     */
    @Override
    public boolean checkP10CertRequest(byte[] transactionID, String requesterDn, byte[] pkcs10CertRequest, String requestedSubjectDn, byte[] pkiMessage) {
        return false;
    }

    /**
     * learn the enrollment status including any new certificate. May respond false
     * in case of internal processing error.
     *
     * @param transactionID the transactionID of the CMP request/response message.
     *                      The transactionID can be used to correlate calls of
     *                      {@link #checkAndModifyCertRequest(byte[], String, byte[], String, byte[])}
     *                      or
     *                      {@link #checkP10CertRequest(byte[], String, byte[], String, byte[])}
     *                      and
     *                      {@link #learnEnrollmentResult(byte[], byte[], String, String, String)}.
     * @param certificate   the new certificate, which is assumed to be ASN.1 DER
     *                      encoded, as returned by the CA. On enrollment failure,
     *                      <code>null</code> is given.
     * @param serialNumber  string representation of the certificate serial number.
     *                      In case of enrollment failure, <code>null</code> is
     *                      given. This parameter is provided for convenience.
     * @param subjectDN     the subject Distinguished Name extracted from the
     *                      certificate or from the certificate request in case of
     *                      enrollment failure. This parameter is provided for
     *                      convenience.
     * @param issuerDN      the issuer Distinguished Name extracted from the
     *                      certificate. In case of enrollment failure,
     *                      <code>null</code> is given. This parameter is provided
     *                      for convenience.
     * @return true on success
     */
    @Override
    public boolean learnEnrollmentResult(byte[] transactionID, byte[] certificate, String serialNumber, String subjectDN, String issuerDN) {
        return true;
    }
}
