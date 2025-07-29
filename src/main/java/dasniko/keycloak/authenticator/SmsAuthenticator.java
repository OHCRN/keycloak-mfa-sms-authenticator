package dasniko.keycloak.authenticator;

import dasniko.keycloak.authenticator.gateway.SmsServiceFactory;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.MessageType;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static dasniko.keycloak.authenticator.OTPConstants.*;
import static java.util.Objects.isNull;
import static org.keycloak.authentication.authenticators.util.AuthenticatorUtils.getDisabledByBruteForceEventError;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@Slf4j
public class SmsAuthenticator implements Authenticator {

	private static final String TPL_CODE = "login-sms.ftl";
	private static final Pattern REGEX_PHONE_NUMBER = Pattern.compile("^\\d{10}$");
	private static final String PHONE_NUMBER_FORMAT = "(\\d{3})(\\d{3})(\\d+)";
	private static final String FIRST_ATTEMPT = "firstAttempt";
	private static final String RESEND_ATTEMPT = "resendAttempt";
	private static final String RESEND_PARAM = "resend";
	private static final String FORMATTED_MOBILE_NUMBER = "formattedMobileNumber";
	private static final String FORMATTED_TTL = "formattedTTL";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();

		int maxResendAttempts = Integer.parseInt(config.getConfig().get(RESEND_CODE_MAX_ATTEMPTS));
		String mobileNumber = user.getFirstAttribute(MOBILE_NUMBER_FIELD);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String sessionId = session.toString();

		if (isNull(authSession.getAuthNote(FIRST_ATTEMPT))) {
			log.debug("Setting first attempt to authenticate");
			// set this note to the session that exists on first screen load
			authSession.setAuthNote(FIRST_ATTEMPT, session.toString());

		}
		String firstAttempt = authSession.getAuthNote(FIRST_ATTEMPT);
		String resendAttempt = authSession.getAuthNote(RESEND_ATTEMPT);

		if (!isNull(resendAttempt) && Integer.parseInt(resendAttempt) >= maxResendAttempts) {
			log.debug("Max resend OTP code attempts reached, disabling user.");
			// disable the user to prevent further resend attempts + block authentication
			user.setEnabled(false);
			// display an error screen
			context.failureChallenge(AuthenticationFlowError.USER_DISABLED,
				context.form().setError("smsResendMaxAttempts")
					.createErrorPage(Response.Status.UNAUTHORIZED));
			// stop code execution
			return;
		}

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);

			// throws error if invalid format
			if (!isValidPhoneNumber(mobileNumber)) {
				String errMessage = theme.getMessages(locale).getProperty("invalidMobileNumber");
				throw new InvalidMobileNumberException(errMessage);
			}
			int ttlInSeconds = getTTL(config);
			Integer formattedTtl = Math.floorDiv(ttlInSeconds, 60);
			String formattedMobileNumber = mobileNumber.replaceFirst(PHONE_NUMBER_FORMAT, "$1-$2-$3");

			authSession.setAuthNote(FORMATTED_MOBILE_NUMBER, formattedMobileNumber);
			authSession.setAuthNote(FORMATTED_TTL, formattedTtl.toString());
			// "resend" will be true if the authenticate function was triggered by clicking the resend button
			String resendNote = authSession.getAuthNote(RESEND_PARAM);
			boolean condition1 = Objects.equals(resendNote, "true");

			// if the page is reloaded, the sessionId changes, so we know it is not the first attempt
			// this prevents triggering a new OTP to be sent if the page is reloaded.
			boolean condition2 = Objects.equals(firstAttempt, sessionId);

			if (condition1 || condition2) {
				// reset the "resend" note to prevent resending the OTP code if the page is reloaded
				authSession.setAuthNote(RESEND_PARAM, null);
				String code = getSecretCode(config);

				authSession.setAuthNote(CODE, code);
				authSession.setAuthNote(CODE_TTL, Long.toString(System.currentTimeMillis() + (ttlInSeconds * 1000L)));

				String smsAuthText = theme.getMessages(locale).getProperty("authCodeText");
				String smsText = String.format(smsAuthText, code);
				SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);
			}
			context.challenge(context.form().setAttribute("realm", context.getRealm()).setAttribute("mobileNumber", formattedMobileNumber).setAttribute("codeTtl", formattedTtl).createForm(TPL_CODE));

		} catch (Exception e) {
			if (e instanceof InvalidMobileNumberException) {
				context.failureChallenge(AuthenticationFlowError.INVALID_USER,
					context.form().setError("smsAuthSmsNotSent", e.getMessage())
						.createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// display error screen with general error message
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError("smsAuthSmsNotSent", "There was an error attempting to send SMS message.")
						.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			}
		}

	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// check context requirements are defined
		codeContextIsValid(context);
		UserModel user = context.getUser();
		// check user is enabled
		boolean isEnabled = userIsEnabled(context, user);
		if (isEnabled) {
			String isResend = context.getHttpRequest().getDecodedFormParameters().getFirst(RESEND_PARAM);
			if (Objects.equals(isResend, "resendCode")) {
				resendCode(context);
			} else {
				// check enteredCode is valid
				validateEnteredCode(context);
			}
		} else {
			context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED,
				context.form().setError("accountTemporarilyDisabledMessage")
					.createErrorPage(Response.Status.UNAUTHORIZED));
		}
	}

	protected String getSecretCode(AuthenticatorConfigModel config) {
		int length = Integer.parseInt(config.getConfig().get(CODE_LENGTH));
		return SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
	}

	/**
	 * Retrieves the OTP time-to-live value from the configuration in the Keycloak Admin UI.
	 * Value is in seconds
	 *
	 * @param config AuthenticatorConfigModel
	 * @return Integer
	 */
	protected Integer getTTL(AuthenticatorConfigModel config) {
		return Integer.parseInt(config.getConfig().get(CODE_TTL));
	}

	/**
	 * Validates that auth session context has required defined values
	 * Will throw an error if code or ttl values are not defined
	 * An error page will be displayed in the UI
	 *
	 * @param context AuthenticationFlowContext
	 */
	protected void codeContextIsValid(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote(CODE);
		String ttl = authSession.getAuthNote(CODE_TTL);
		if (isNull(code) || isNull(ttl)) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	/**
	 * Checks that the OTP code entered by a user matches the code in the auth session context
	 *
	 * @param context AuthenticationFlowContext
	 * @return boolean
	 */
	private boolean enteredCodeIsValid(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst(CODE);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote(CODE);
		return enteredCode.equals(code);
	}

	/**
	 * Validates that the OTP code entered by a user is correct, and still valid for use in the current session.
	 * On success, OTP flow is complete.
	 * If either check fails, will set an error in the context form, and display an error screen in the UI indicating the type of error.
	 *
	 * @param context AuthenticationFlowContext
	 */
	protected void validateEnteredCode(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String ttl = authSession.getAuthNote(CODE_TTL);
		String mobileNumber = authSession.getAuthNote(FORMATTED_MOBILE_NUMBER);
		String formattedTtl = authSession.getAuthNote(FORMATTED_TTL);

		boolean isValid = enteredCodeIsValid(context);
		if (isValid) {
			// ttl is still valid
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				// expired
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("authCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				context.success();
			}
		} else {
			// invalid
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {

				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setAttribute("realm", context.getRealm()).setAttribute("mobileNumber", mobileNumber).setAttribute("codeTtl", formattedTtl)
						.setError("authCodeInvalid").createForm(TPL_CODE));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}

	private void incrementedResendAttempt(AuthenticationSessionModel authSession) {
		String resendAttempt = authSession.getAuthNote(RESEND_ATTEMPT);
		int incremented = isNull(resendAttempt) ? 1 : Integer.parseInt(resendAttempt) + 1;
		authSession.setAuthNote(RESEND_ATTEMPT, Integer.toString(incremented));
	}

	/**
	 * Triggers a new authentication flow that will resend a new OTP code and invalidate the previous OTP code.
	 *
	 * @param context AuthenticationFlowContext
	 */
	protected void resendCode(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote(RESEND_PARAM, "true");
		// increment the "resendAttempt" auth note value
		incrementedResendAttempt(authSession);
		// display a message that a new OTP code has been sent
		context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
			context.form().setAttribute("realm", context.getRealm())
				.setMessage(MessageType.INFO, "authCodeResent").createForm(SmsAuthenticator.TPL_CODE));
		authenticate(context);
	}

	@Override
	public boolean requiresUser() {
		return true;
	}


	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		// this will only work if you have the required action from here configured:
		// https://github.com/dasniko/keycloak-extensions-demo/tree/main/requiredaction
		//	this required action example enforces the user to update their mobile phone number, if not already set.
		//	since we ask for this info on registration, or we use email which must be defined, it is not necessary
		//	user.addRequiredAction("mobile-number-ra");
	}

	@Override
	public void close() {
	}

	/**
	 * Checks if the current User isEnabled status.
	 * If the user is disabled due to a Brute Force Error or other reason, triggers error messaging in the browser form.
	 *
	 * @param context AuthenticationFlowContext
	 * @return boolean
	 */
	public boolean userIsEnabled(AuthenticationFlowContext context, UserModel user) {
		if (isDisabledByBruteForce(context, user)) {
			context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED,
				context.form().setError("accountTemporarilyDisabledMessage", "Your account has been temporarily disabled")
					.createErrorPage(Response.Status.UNAUTHORIZED));
			return false;
		}
		if (!user.isEnabled()) {
			context.getEvent().user(user);
			context.getEvent().error(Errors.USER_DISABLED);

			context.failureChallenge(AuthenticationFlowError.USER_DISABLED,
				context.form().setError("accountPermanentlyDisabledMessage")
					.createErrorPage(Response.Status.UNAUTHORIZED));
			return false;
		}
		return true;
	}

	protected boolean isDisabledByBruteForce(AuthenticationFlowContext context, UserModel user) {
		String bruteForceError = getDisabledByBruteForceEventError(context, user);
		if (!isNull(bruteForceError)) {
			context.getEvent().user(user);
			context.getEvent().error(bruteForceError);
			return true;
		}
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		// return true ensures this flow will always run if SMS OTP flow is enabled as a step in the Browser Authentication flow
		return true;
	}

	private boolean isValidPhoneNumber(String phoneNumber) {
		if (isNull(phoneNumber)) {
			return false;
		}
		Matcher validPhoneNumber = REGEX_PHONE_NUMBER.matcher(phoneNumber);
		return validPhoneNumber.matches();
	}

}
