package dasniko.keycloak.authenticator;

import lombok.experimental.UtilityClass;

@UtilityClass
public class OTPConstants {
	public String CODE = "code";
	public String CODE_LENGTH = "length";
	public String CODE_TTL = "ttl";
	public String SIMULATION_MODE = "simulation";
	public String MOBILE_NUMBER_FIELD = "mobilePhoneNumber";
	public String ORIGINATION_NUMBER = "originationNumber";
	public String RESEND_CODE_MAX_ATTEMPTS = "resendCodeMaxAttempts";
	public String RESEND_ATTEMPT_LAST_TIMESTAMP = "resendAttemptLastTimestamp";
	public String RESEND_CODE_RESET_PERIOD = "resendCodeResetPeriod";
	public String RESEND_ATTEMPT_COUNT = "resendAttemptCount";

}
