{**
 * templates/settings.tpl
 *}
<script>
	$(function() {ldelim}
		$('#magicLoginSettings').pkpHandler('$.pkp.controllers.form.AjaxFormHandler');
	{rdelim});
</script>

<form
	class="pkp_form"
	id="magicLoginSettings"
	method="POST"
	action="{url router=$smarty.const.ROUTE_COMPONENT op="manage" category="generic" plugin=$pluginName verb="settings" save=true}"
>
	{csrf}
	{fbvFormArea id="magicLoginArea"}
		{fbvFormSection list=true}
			{fbvElement type="checkbox" id="enabled" label="plugins.generic.magicLogin.settings.enabled" checked=$enabled}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.magicLogin.settings.ttl"}
			{fbvElement type="text" id="ttlMinutes" value=$ttlMinutes size=$fbvStyles.size.SMALL}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.magicLogin.settings.minInterval"}
			{fbvElement type="text" id="minIntervalSeconds" value=$minIntervalSeconds size=$fbvStyles.size.SMALL}
		{/fbvFormSection}
	{/fbvFormArea}
	{fbvFormButtons submitText="common.save"}
</form>

<div class="magicLoginRecentActivity">
	<h3>{translate key="plugins.generic.magicLogin.activity.title"}</h3>
	{if $recentAttempts && $recentAttempts|@count > 0}
		<table class="listing">
			<tr>
				<th>{translate key="plugins.generic.magicLogin.activity.time"}</th>
				<th>{translate key="plugins.generic.magicLogin.activity.event"}</th>
				<th>{translate key="plugins.generic.magicLogin.activity.user"}</th>
				<th>{translate key="plugins.generic.magicLogin.activity.ip"}</th>
			</tr>
			{foreach from=$recentAttempts item=attempt}
				<tr>
					<td>{$attempt.time|escape}</td>
					<td>{$attempt.event|escape}</td>
					<td>{$attempt.user|escape}</td>
					<td>{$attempt.ip|escape}</td>
				</tr>
			{/foreach}
		</table>
	{else}
		<p>{translate key="plugins.generic.magicLogin.activity.empty"}</p>
	{/if}
</div>
