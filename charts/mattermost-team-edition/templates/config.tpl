{{- define "config.tpl" -}}
{
    "ServiceSettings": {
        "EnableGifPicker": false,
        "CloseUnusedDirectMessages": false,
        "EnableEmailInvitations": true,
        "WebsocketURL": "",
        "TLSOverwriteCiphers": [],
        "TLSMinVer": 1.2,
        "WriteTimeout": 300,
        "EnableChannelViewedMessages": true,
        "AllowCookiesForSubdomains": false,
        "ExperimentalEnableHardenedMode": false,
        "TLSStrictTransportMaxAge": 63072000,
        "GoroutineHealthThreshold": -1,
        "ExperimentalGroupUnreadChannels": "disabled",
        "EnableAPITeamDeletion": false,
        "ExperimentalEnableDefaultChannelLeaveJoinMessages": true,
        "TrustedProxyIPHeader": [X-Forwarded-For X-Real-IP],
        "ExperimentalLdapGroupSync": false,
        "EnableBotAccountCreation": false,
        "EnableUserAccessTokens": false,
        "CorsDebug": false,
        "MinimumHashtagLength": 3,
        "EnablePreviewFeatures": true,
        "DisableBotsWhenOwnerIsDeactivated": true,
        "CorsExposedHeaders": "",
        "EnableEmojiPicker": true,
        "TLSStrictTransport": false,
        "AllowedUntrustedInternalConnections": "",
        "SessionIdleTimeoutInMinutes": 43200,
        "ExperimentalEnableAuthenticationTransfer": true,
        "ExperimentalStrictCSRFEnforcement": false,
        "ExperimentalChannelOrganization": false,
        "DisableLegacyMFA": false,

        "SiteURL": "{{ .Values.global.siteUrl }}",
        "LicenseFileLocation": "",
        "ListenAddress": ":{{ .Values.mattermostApp.service.internalPort }}",
        "ConnectionSecurity": "",
      	"CorsAllowCredentials": "false"
        "TLSCertFile": "",
        "TLSKeyFile": "",
        "UseLetsEncrypt": false,
        "LetsEncryptCertificateCacheFile": "./config/letsencrypt.cache",
        "Forward80To443": false,
        "ReadTimeout": 300,
        "WriteTimeout": 300,
        "MaximumLoginAttempts": 10,
        "GoroutineHealthThreshold": -1,
        "GoogleDeveloperKey": "",
        "EnableTutorial": true,
        "EnableOAuthServiceProvider": false,
        "EnableIncomingWebhooks": true,
        "EnableOutgoingWebhooks": true,
        "EnableCommands": true,
        "EnableOnlyAdminIntegrations": false,
        "EnablePostUsernameOverride": false,
        "EnablePostIconOverride": false,
        "EnableLinkPreviews": {{ .Values.global.enableLinkPreviews }},
        "EnableTesting": false,
        "EnableDeveloper": false,
        "EnableSecurityFixAlert": true,
        "EnableInsecureOutgoingConnections": false,
        "EnableMultifactorAuthentication": false,
        "EnforceMultifactorAuthentication": false,
        "AllowCorsFrom": "",
        "SessionLengthWebInDays": 30,
        "SessionLengthMobileInDays": 30,
        "SessionLengthSSOInDays": 30,
        "SessionCacheInMinutes": 10,
        "WebsocketSecurePort": 443,
        "WebsocketPort": 80,
        "EnableCustomEmoji": {{ .Values.global.enableCustomEmoji }},
        "RestrictCustomEmojiCreation": "all",
        "RestrictPostDelete": "all",
        "AllowEditPost": "always",
        "PostEditTimeLimit": 300,
        "TimeBetweenUserTypingUpdatesMilliseconds": 5000,
        "EnablePostSearch": true,
        "EnableUserTypingMessages": true,
        "EnableUserStatuses": true,
        "ClusterLogTimeoutMilliseconds": 2000
    },
    "ExperimentalSettings": {
        "EnableClickToReply": false,
        "LinkMetadataTimeoutMilliseconds": 5000,
        "RestrictSystemAdmin": false,
        "ClientSideCertEnable": false,
        "ClientSideCertCheck": "secondary"
    },
    "NotificationLogSettings": {
        "ConsoleJson": true,
        "EnableFile": true,
        "FileLevel": "INFO",
        "FileJson": true,
        "FileLocation": "",
        "EnableConsole": true,
        "ConsoleLevel": "DEBUG"
    },
    "TeamSettings": {
        "TeammateNameDisplay": "username",

        "SiteName": {{ .Values.global.siteName | quote }},
        "MaxUsersPerTeam": 50000,
        "EnableTeamCreation": {{ .Values.global.enableTeamCreation }},
        "EnableUserCreation": {{ .Values.global.enableUserCreation }},
        "EnableOpenServer": {{ .Values.global.enableOpenServer }},
        "RestrictCreationToDomains": "",
        "EnableCustomBrand": false,
        "CustomBrandText": "",
        "CustomDescriptionText": "",
        "RestrictDirectMessage": "any",
        "RestrictTeamInvite": "all",
        "RestrictPublicChannelManagement": "all",
        "RestrictPrivateChannelManagement": "all",
        "RestrictPublicChannelCreation": "all",
        "RestrictPrivateChannelCreation": "all",
        "RestrictPublicChannelDeletion": "all",
        "RestrictPrivateChannelDeletion": "all",
        "RestrictPrivateChannelManageMembers": "all",
        "UserStatusAwayTimeout": 300,
        "MaxChannelsPerTeam": 50000,
        "MaxNotificationsPerChannel": 1000
    },
    "SqlSettings": {
        {{- if .Values.global.features.database.useInternal }}
        "DriverName": "mysql",
        "DataSource": "{{ .Values.mysqlha.mysqlha.mysqlUser }}:{{ .Values.mysqlha.mysqlha.mysqlPassword }}@tcp({{ .Release.Name }}-mysqlha-0.{{ .Release.Name }}-mysqlha:3306)/{{ .Values.mysqlha.mysqlha.mysqlDatabase }}?charset=utf8mb4,utf8&readTimeout=30s&writeTimeout=30s",
        "DataSourceReplicas": ["{{ .Values.mysqlha.mysqlha.mysqlUser }}:{{ .Values.mysqlha.mysqlha.mysqlPassword }}@tcp({{ .Release.Name }}-mysqlha-readonly:3306)/{{ .Values.mysqlha.mysqlha.mysqlDatabase }}?charset=utf8mb4,utf8&readTimeout=30s&writeTimeout=30s"],
        {{- else }}
        "DriverName": "{{ .Values.global.features.database.external.driver }}",
        "DataSource": "{{ .Values.global.features.database.external.dataSource }}",
        "DataSourceReplicas": [
        {{ range $index, $element := .Values.global.features.database.external.dataSourceReplicas }}
        {{- if $index }},{{- end }}
        {{ $element }}
        {{ end }}
        ],
        {{- end }}
        "DataSourceSearchReplicas": [],
        "MaxIdleConns": 20,
        "MaxOpenConns": 35,
        "Trace": false,
        "AtRestEncryptKey": "{{ randAlphaNum 32 }}",
        "QueryTimeout": 30
    },
    "LogSettings": {
        "EnableConsole": true,
        "ConsoleLevel": "INFO",
        "EnableFile": true,
        "FileLevel": "INFO",
        "FileFormat": "",
        "FileLocation": "",
        "EnableWebhookDebugging": true,
        "EnableDiagnostics": true
    },
    "PasswordSettings": {
        "MinimumLength": 5,
        "Lowercase": false,
        "Number": false,
        "Uppercase": false,
        "Symbol": false
    },
    "ElasticsearchSettings": {
        "Sniff": true,
        "PostIndexReplicas": 1,
        "ChannelIndexShards": 1,
        "IndexPrefix": "",
        "BulkIndexingTimeWindowSeconds": 3600,
        "ConnectionUrl": "http://dockerhost:9200",
        "Username": "elastic",
        "EnableIndexing": false,
        "EnableSearching": false,
        "EnableAutocomplete": false,
        "PostIndexShards": 1,
        "ChannelIndexReplicas": 1,
        "UserIndexShards": 1,
        "PostsAggregatorJobStartTime": "03:00",
        "AggregatePostsAfterDays": 365,
        "LiveIndexingBatchSize": 1,
        "RequestTimeoutSeconds": 30,
        "Password": "changeme",
        "UserIndexReplicas": 1
    },
    "MessageExportSettings": {
        "EnableExport": false,
        "ExportFormat": "actiance",
        "DailyRunTime": "01:00",
        "ExportFromTimestamp": 0,
        "BatchSize": 10000,
        "GlobalRelaySettings": {
            "SmtpPassword": "",
            "EmailAddress": "",
            "CustomerType": "A9",
            "SmtpUsername": ""
        }
    },
    "FileSettings": {

        "AmazonS3SSE": false,
        "EnableMobileUpload": true,
        "EnableMobileDownload": true,

        "EnableFileAttachments": true,
        "MaxFileSize": 52428800,
        "DriverName": "amazons3",
        "Directory": "./data/",
        "EnablePublicLink": false,
        "PublicLinkSalt": "{{ randAlphaNum 32 }}",
        "ThumbnailWidth": 120,
        "ThumbnailHeight": 100,
        "PreviewWidth": 1024,
        "PreviewHeight": 0,
        "ProfileWidth": 128,
        "ProfileHeight": 128,
        "InitialFont": "luximbi.ttf",
        "AmazonS3AccessKeyId": "{{ .Values.minio.accessKey }}",
        "AmazonS3SecretAccessKey": "{{ .Values.minio.secretKey }}",
        "AmazonS3Bucket": "{{ .Values.minio.defaultBucket.name }}",
        "AmazonS3Region": "",
        "AmazonS3Endpoint": "{{ .Release.Name }}-minio:9000",
        "AmazonS3SSL": false,
        "AmazonS3SignV2": false
    },
    "EmailSettings": {
        "EnablePreviewModeBanner": true,
        "LoginButtonColor": "#0000",
        "LoginButtonBorderColor": "#2389D7",
        "EmailNotificationContentsType": "full",
        "EnableSMTPAuth": false,
        "SMTPPort": 2500,
        "UseChannelInEmailNotifications": false,
        "ReplyToAddress": "test@example.com",

        "EnableSignUpWithEmail": true,
        "EnableSignInWithEmail": true,
        "EnableSignInWithUsername": true,
        "SendEmailNotifications": {{ .Values.global.sendEmailNotifications }},
        "RequireEmailVerification": {{ .Values.global.requireEmailVerification }},
        "FeedbackName": {{ .Values.global.feedbackName | quote }},
        "FeedbackEmail": {{ .Values.global.feedbackEmail | quote }},
        "FeedbackOrganization": {{ .Values.global.feedbackOrganization | quote }},
        "SMTPUsername": {{ .Values.global.smtpUsername | quote }},
        "SMTPPassword": {{ .Values.global.smtpPassword | quote }},
        "SMTPServer": {{ .Values.global.smtpServer | quote }},
        "SMTPPort": {{ .Values.global.smtpPort | quote }},
        "ConnectionSecurity": {{ .Values.global.connectionSecurity | quote }},
        "InviteSalt": {{ randAlphaNum 32 | quote }},
        "SendPushNotifications": {{ .Values.global.features.notifications.push.enabled }},
        {{- if .Values.global.features.notifications.push.useHPNS }}
        "PushNotificationServer": "https://push.mattermost.com",
        {{- else }}
        "PushNotificationServer": "http://{{ .Release.Name }}-mattermost-push-proxy:8066",
        {{- end }}
        "PushNotificationContents": "generic",
        "EnableEmailBatching": false,
        "EmailBatchingBufferSize": 256,
        "EmailBatchingInterval": 30,
        "SkipServerCertificateVerification": false
    },
    "RateLimitSettings": {
        "Enable": false,
        "PerSec": 10,
        "MaxBurst": 100,
        "MemoryStoreSize": 10000,
        "VaryByRemoteAddr": true,
        "VaryByUser": false,
        "VaryByHeader": ""
    },
    "PrivacySettings": {
        "ShowEmailAddress": true,
        "ShowFullName": true
    },
    "SupportSettings": {
        "CustomTermsOfServiceEnabled": "false",
        "CustomTermsOfServiceReAcceptancePeriod": "365",
        "TermsOfServiceLink": "https://about.mattermost.com/default-terms/",
        "PrivacyPolicyLink": "https://about.mattermost.com/default-privacy-policy/",
        "AboutLink": "https://about.mattermost.com/default-about/",
        "HelpLink": "https://about.mattermost.com/default-help/",
        "ReportAProblemLink": "https://about.mattermost.com/default-report-a-problem/",
        "SupportEmail": "feedback@mattermost.com"
    },
    "AnnouncementSettings": {
        "EnableBanner": false,
        "BannerText": "",
        "BannerColor": "#f2a93b",
        "BannerTextColor": "#333333",
        "AllowBannerDismissal": true
    },
    "GitLabSettings": {
        "Enable": false,
        "Secret": "",
        "Id": "",
        "Scope": "",
        "AuthEndpoint": "",
        "TokenEndpoint": "",
        "UserApiEndpoint": ""
    },
    "ImageProxySettings": {
        "RemoteImageProxyOptions": "",
        "Enable": "false",
        "ImageProxyType": "local",
        "RemoteImageProxyURL": ""
    },
    "GoogleSettings": {
        "Enable": false,
        "Secret": "",
        "Id": "",
        "Scope": "profile email",
        "AuthEndpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "TokenEndpoint": "https://www.googleapis.com/oauth2/v4/token",
        "UserApiEndpoint": "https://www.googleapis.com/plus/v1/people/me"
    },
    "Office365Settings": {
        "Enable": false,
        "Secret": "",
        "Id": "",
        "Scope": "User.Read",
        "AuthEndpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "TokenEndpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "UserApiEndpoint": "https://graph.microsoft.com/v1.0/me"
    },
    "LdapSettings": {

        "LoginButtonTextColor": "#2389D7",
        "GroupFilter": "",
        "GroupIdAttribute": "",
        "LoginButtonBorderColor": "#2389D7",
        "EnableSync": false,
        "LoginIdAttribute": "",
        "LoginButtonColor": "#0000",

        "Enable": false,
        "LdapServer": "",
        "LdapPort": 389,
        "ConnectionSecurity": "",
        "BaseDN": "",
        "BindUsername": "",
        "BindPassword": "",
        "UserFilter": "",
        "FirstNameAttribute": "",
        "LastNameAttribute": "",
        "EmailAttribute": "",
        "UsernameAttribute": "",
        "NicknameAttribute": "",
        "IdAttribute": "",
        "PositionAttribute": "",
        "SyncIntervalMinutes": 60,
        "SkipCertificateVerification": false,
        "QueryTimeout": 60,
        "MaxPageSize": 0,
        "LoginFieldName": ""
    },
    "ComplianceSettings": {
        "Enable": false,
        "Directory": "./data/",
        "EnableDaily": false
    },
    "LocalizationSettings": {
        "DefaultServerLocale": "en",
        "DefaultClientLocale": "en",
        "AvailableLocales": ""
    },
    "SamlSettings": {
        "LoginButtonBorderColor": "#2389D7",
        "LoginButtonTextColor": "#ffffff",
        "IdAttribute": "",
        "LoginButtonColor": "#34a28b",
        "EnableSyncWithLdapIncludeAuth": "false",
        "ScopingIDPProviderId": "",
        "ScopingIDPName": "",
        "EnableSyncWithLdap": "false",

        "Enable": false,
        "Verify": true,
        "Encrypt": true,
        "IdpUrl": "",
        "IdpDescriptorUrl": "",
        "AssertionConsumerServiceURL": "",
        "IdpCertificateFile": "",
        "PublicCertificateFile": "",
        "PrivateKeyFile": "",
        "FirstNameAttribute": "",
        "LastNameAttribute": "",
        "EmailAttribute": "",
        "UsernameAttribute": "",
        "NicknameAttribute": "",
        "LocaleAttribute": "",
        "PositionAttribute": "",
        "LoginButtonText": "With SAML"
    },
    "NativeAppSettings": {
        "AppDownloadLink": "https://about.mattermost.com/downloads/",
        "AndroidAppDownloadLink": "https://about.mattermost.com/mattermost-android-app/",
        "IosAppDownloadLink": "https://about.mattermost.com/mattermost-ios-app/"
    },
    "ClientRequirements": {
        "androidlatestversion": "",
        "AndroidMinVersion": "",
        "DesktopLatestVersion": "",
        "DesktopMinVersion": "",
        "IosLatestVersion": "",
        "IosMinVersion": ""
    },
    "DisplaySettings": {
        "CustomUrlSchemes": [],
        "ExperimentalTimezone": true
    },
    "ClusterSettings": {
        "ReadOnlyConfig": true,
        "StreamingPort": "8075",
        "MaxIdleConnsPerHost": "128",
        "IdleConnTimeoutMilliseconds": "90000",
        "MaxIdleConns": "100",

        "Enable": true,
        "ClusterName": "{{ .Release.Name }}-cluster",
        "OverrideHostname": "",
        "UseIpAddress": true,
        "UseExperimentalGossip": true,
        "ReadOnlyConfig": false,
        "GossipPort": 8074,
        "StreamingPort": 8075
    },
    "MetricsSettings": {
        "Enable": true,
        "BlockProfileRate": 0,
        "ListenAddress": ":8067"
    },
    "AnalyticsSettings": {
        "MaxUsersForStatistics": 2500
    },
    "WebrtcSettings": {
        "Enable": false,
        "GatewayWebsocketUrl": "",
        "GatewayAdminUrl": "",
        "GatewayAdminSecret": "",
        "StunURI": "",
        "TurnURI": "",
        "TurnUsername": "",
        "TurnSharedKey": ""
    },
    "PluginSettings": {
        "Enable": true,
        "EnableHealthCheck": "true",
        "EnableUploads": true,
        "Directory": "./plugins",
        "ClientDirectory": "./client/plugins",
        "Plugins": {},
        "PluginStates": {}
    },
    "DataRetentionSettings": {
        "MessageRetentionDays": "365",
        "FileRetentionDays": "365",
        "DeletionJobStartTime": "02:00",
        "EnableMessageDeletion": false,
        "EnableFileDeletion": false,

        "Enable": false
    }
    {{- if .Values.global.features.jobserver.enabled -}}
    ,
    "JobSettings": {
        "RunJobs": false,
        "RunScheduler": false
    }
    {{- end }}
}
{{- end }}
