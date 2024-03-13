package com.siemens.pki.lightweightcmpra.plugin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import java.net.http.HttpClient;

public class HttpInventoryInterfaceImpl extends InventoryPluginBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpInventoryInterfaceImpl.class);

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
        ObjectNode json = null;
        try {
            json = createJson(transactionID, requesterDn, certTemplate, requestedSubjectDn, pkiMessage);
        } catch (JsonProcessingException e) {
            LOGGER.error("inventory error while checking certificate request:", e);
            return NEGATIVE_CHECK_RESULT;
        }
        // Stringify json
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonString;

        try {
            jsonString = objectMapper.writeValueAsString(json);
        } catch (JsonProcessingException e) {
            LOGGER.error("inventory error while checking certificate request:", e);
            return NEGATIVE_CHECK_RESULT;
        }


        try {
            // Create an instance of HttpClient
            HttpClient httpClient = HttpClient.newHttpClient();
            // Create an instance of HttpPost with the desired URL
            String postUrl = System.getProperty("RA_INVENTORY_URL");

            HttpRequest request = HttpRequest
                    .newBuilder()
                    .uri(URI.create(postUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonString))
                    .header("Content-type", "application/json")
                    .build();

            // Execute the request and obtain the response
            HttpResponse<String> httpResponse =httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Parse response

            // return validation result
            return new CheckAndModifyResult() {
                @Override
                public byte[] getUpdatedCertTemplate() {
                    return null;
                }

                @Override
                public boolean isGranted() {
                    return httpResponse.statusCode() == 200;
                }
            };

        } catch (RuntimeException | InterruptedException | IOException e) {
            LOGGER.error("inventory error while checking certificate request:", e);
            return NEGATIVE_CHECK_RESULT;
        }
    }

}
