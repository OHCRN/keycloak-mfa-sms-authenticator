package dasniko.keycloak.authenticator;

import dasniko.keycloak.authenticator.gateway.SmsServiceFactory;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static dasniko.keycloak.authenticator.OTPConstants.*;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@Slf4j
public class SmsAuthenticator extends OTPAuthenticator {

	protected static final String TPL_CODE = "login-sms.ftl";
	private static final Pattern REGEX_PHONE_NUMBER = Pattern.compile("^\\d{10}$");
	private static final String PHONE_NUMBER_FORMAT = "(\\d{3})(\\d{3})(\\d+)";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();

		String mobileNumber = user.getFirstAttribute(MOBILE_NUMBER_FIELD);

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);

			// throws error if invalid format
			if (!isValidPhoneNumber(mobileNumber)) {
				String errMessage = theme.getMessages(locale).getProperty("invalidMobileNumber");
				throw new InvalidMobileNumberException(errMessage);
			}

			int ttlInSeconds = getTTL(config);
			String code = getSecretCode(config);

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			authSession.setAuthNote(CODE, code);
			authSession.setAuthNote(CODE_TTL, Long.toString(System.currentTimeMillis() + (ttlInSeconds * 1000L)));

			String smsAuthText = theme.getMessages(locale).getProperty("authCodeText");
			Integer formattedTtl = Math.floorDiv(ttlInSeconds, 60);
			String smsText = String.format(smsAuthText, code);
			String formattedMobileNumber = mobileNumber.replaceFirst(PHONE_NUMBER_FORMAT, "$1-$2-$3");

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

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

		// check enteredCode is valid
		validateEnteredCode(context, TPL_CODE);
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		// return true ensures this flow will always run if SMS OTP flow is enabled as a step in the Browser Authentication flow
		return true;
		// this configuration prevents the OTP form from showing if user has no MOBILE_NUMBER_FIELD attribute
		// will instead use EmailAuthenticator flow
		// return user.getFirstAttribute(MOBILE_NUMBER_FIELD) != null;
	}

	private boolean isValidPhoneNumber(String phoneNumber) {
		if (phoneNumber == null) {
			return false;
		}
		Matcher validPhoneNumber = REGEX_PHONE_NUMBER.matcher(phoneNumber);
		return validPhoneNumber.matches();
	}

}
