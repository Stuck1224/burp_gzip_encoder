import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPOutputStream;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi montoyaApi) {

        montoyaApi.extension().setName("GZIP Payload Processor");

        montoyaApi.intruder().registerPayloadProcessor(new PayloadProcessor() {

            @Override
            public String displayName() {
                return "GZIP";
            }

            @Override
            public PayloadProcessingResult processPayload(PayloadData payloadData) {

                byte[] input = payloadData.currentPayload().getBytes();

                try {
                    ByteArrayOutputStream output = new ByteArrayOutputStream();

                    GZIPOutputStream gzip = new GZIPOutputStream(output);

                    gzip.write(input);
                    gzip.close();

                    byte[] compressed = output.toByteArray();

                    return PayloadProcessingResult.usePayload(
                            ByteArray.byteArray(compressed)
                    );

                } catch (IOException e) {
                    return PayloadProcessingResult.usePayload(
                            ByteArray.byteArray(input)
                    );
                }
            }
        });
    }
}
