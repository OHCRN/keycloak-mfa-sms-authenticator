<#import "template.ftl" as layout>
<@layout.emailLayout>
	${kcSanitize(msg("otpEmailBody", code))?no_esc}
</@layout.emailLayout>
