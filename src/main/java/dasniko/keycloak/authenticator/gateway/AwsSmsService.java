package dasniko.keycloak.authenticator.gateway;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.*;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@Slf4j
public class AwsSmsService implements SmsService {

	private static final SnsClient sns = SnsClient.builder().build();
	private final String originationNumber;
	private static final String smsType = "Transactional";
	private static final String countryCode = "+1";

	AwsSmsService(Map<String, String> config) {
		// the config arg here is the config provided from the Keycloak Browser Flow form, when you set up the authentication extension
		originationNumber = config.get("originationNumber");
	}

	@Override
	public void send(String phoneNumber, String message) throws AwsServiceException {
		Map<String, MessageAttributeValue> messageAttributes = new HashMap<>();
		messageAttributes.put("AWS.SNS.SMS.SMSType",
			MessageAttributeValue.builder().stringValue(smsType).dataType("String").build());
		messageAttributes.put("AWS.MM.SMS.OriginationNumber", MessageAttributeValue.builder().stringValue(originationNumber).dataType("String").build());

		try {
			String numberWithCountryCode = countryCode + phoneNumber;

			PublishRequest request = PublishRequest.builder()
				.message(message)
				.phoneNumber(numberWithCountryCode)
				.messageAttributes(messageAttributes)
				.build();

			PublishResponse response = sns.publish(request);
			log.debug(response.messageId() + " - Message successfully sent, with response status: " + response.sdkHttpResponse().statusCode());
		} catch (AwsServiceException e) {
			log.error("Error from AWS SNS service - " + e.getMessage());
			throw e;
		}

	}

}
