package dasniko.keycloak.authenticator;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static dasniko.keycloak.authenticator.OTPConstants.*;

@Slf4j
public class EmailAuthenticator extends OTPAuthenticator {
	private static final String TPL_CODE = "login-email.ftl";
	private static final String EMAIL_OTP_TEMPLATE = "email-otp.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();

		int ttl = getTTL(config);
		String code = getSecretCode(config);

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote(OTPConstants.CODE, code);
		authSession.setAuthNote(OTPConstants.CODE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		RealmModel realm = context.getRealm();

		EmailTemplateProvider emailTemplateProvider = context.getSession().getProvider(EmailTemplateProvider.class);
		emailTemplateProvider.setRealm(realm);
		emailTemplateProvider.setUser(user);

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String otpAuthText = theme.getMessages(locale).getProperty("authCodeText");
			String otpText = String.format(otpAuthText, code, Math.floorDiv(ttl, 60));

			Map<String, Object> msgParams = new HashMap<>();
			msgParams.put("code", otpText);

			String subjectLine = theme.getMessages(locale).getProperty("emailAuthSubject");
			emailTemplateProvider.send(subjectLine, EMAIL_OTP_TEMPLATE, msgParams);

			context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
		} catch (Exception e) {
			context.failure(AuthenticationFlowError.INTERNAL_ERROR);
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
		return user.getFirstAttribute(MOBILE_NUMBER_FIELD) == null;
	}

}
