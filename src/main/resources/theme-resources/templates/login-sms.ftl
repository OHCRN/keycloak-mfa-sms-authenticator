<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false displayRequiredFields=false; section>
	<#if section = "sms-info">
		<h2 id="sms-title">${msg("smsAuthTitle")}</h2>
		<div class="sms-instructions">
			${msg("smsAuthInstruction1", mobileNumber)?no_esc}
			${msg("smsAuthInstruction2", codeTtl)}
		</div>
	<#elseif section = "form">
		<form id="kc-sms-code-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="code" class="${properties.kcLabelClass!}">${msg("smsAuthLabel")}</label>
					<input type="text" id="code" name="code" class="${properties.kcInputClass!}" autofocus/>
				</div>
			</div>
			<div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input
						class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
						type="submit" value="${msg("doVerifyCode")}"/>
				</div>
			</div>
		</form>
	<#elseif section = "resend">
		<div id="retry-wrapper" class="${properties.kcFormButtonsClass!}"><a class="retry-code" href="">${msg("resendCode")}</a></div>
	</#if>
</@layout.registrationLayout>
