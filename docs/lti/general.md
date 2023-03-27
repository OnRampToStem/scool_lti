# General LTI 1.3 Integration

# Resources

* [LTI 1.3 Core Specification][ims_lti_1.3_core_spec]
* [LTI 1.3 Implementation Guide][ims_lti_1.3_impl_guide]
* [IMS Security Framework][ims_sec]
* [Configuring LTI with Canvas][canvas_lti]
* [Canvas auth for LTI Advantage Services][canvas_lti_adv_auth]
* [Canvas client_credentials oauth process][canvas_oauth_login]
* [OAuth Playground][oauth_playground]
* [OpenID Connect Core 1.0][oidc_core]
* [VitalSource Example Setup](https://success.vitalsource.com/hc/en-gb/articles/360052315753-LTI-1-3-Tool-Setup-Instructions-for-Canvas)


# Samples

## Sample LtiResourceLinkRequest

Using the IMS RI, the following is an example IDToken that is returned from a
resource link launch request.

```json
{
    "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
    "given_name": "Sally",
    "family_name": "Bednar",
    "middle_name": "Schroeder",
    "picture": "http://example.org/Sally.jpg",
    "email": "Sally.Bednar@example.org",
    "name": "Sally Schroeder Bednar",
    "https://purl.imsglobal.org/spec/lti/claim/roles": [
        "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
        "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student",
        "http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor"
    ],
    "https://purl.imsglobal.org/spec/lti/claim/role_scope_mentor": [
        "a62c52c02ba262003f5e"
    ],
    "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
        "id": "36833",
        "title": "Test Local Resource Link",
        "description": "Test Local Resource Link"
    },
    "https://purl.imsglobal.org/spec/lti/claim/context": {
        "id": "23506",
        "label": "Test Course",
        "title": "Test Course Title",
        "type": [
            "Test Course Context"
        ]
    },
    "https://purl.imsglobal.org/spec/lti/claim/tool_platform": {
        "name": "STEM SCALE Test Platform",
        "contact_email": "",
        "description": "",
        "url": "",
        "product_family_code": "",
        "version": "1.0",
        "guid": 2095
    },
    "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint": {
        "scope": [
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
            "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/score"
        ],
        "lineitems": "https://lti-ri.imsglobal.org/platforms/2095/contexts/23506/line_items"
    },
    "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
        "context_memberships_url": "https://lti-ri.imsglobal.org/platforms/2095/contexts/23506/memberships",
        "service_versions": [
            "2.0"
        ]
    },
    "https://purl.imsglobal.org/spec/lti-ces/claim/caliper-endpoint-service": {
        "scopes": [
            "https://purl.imsglobal.org/spec/lti-ces/v1p0/scope/send"
        ],
        "caliper_endpoint_url": "https://lti-ri.imsglobal.org/platforms/2095/sensors",
        "caliper_federated_session_id": "urn:uuid:484bf553eef95ae491cb"
    },
    "iss": "https://lti-ri.imsglobal.org",
    "aud": "stem_scale_7984546158",
    "iat": 1621898881,
    "exp": 1621899181,
    "sub": "91492b4cb0eb6601b381",
    "nonce": "67225d43d5751c1f4221",
    "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
    "locale": "en-US",
    "https://purl.imsglobal.org/spec/lti/claim/launch_presentation": {
        "document_target": "iframe",
        "height": 320,
        "width": 240,
        "return_url": "https://lti-ri.imsglobal.org/platforms/2095/returns"
    },
    "https://www.example.com/extension": {
        "color": "violet"
    },
    "https://purl.imsglobal.org/spec/lti/claim/custom": {
        "myCustomValue": "123"
    },
    "https://purl.imsglobal.org/spec/lti/claim/deployment_id": "1",
    "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "https://app-local.fresnostate.edu:8443/lti/v1.3/launches"
}
```

## Sample Canvas Tool Config

https://canvas.instructure.com/doc/api/file.lti_dev_key_config.html#anatomy-of-a-json-configuration

```json
{
   "title":"The Best Tool",
   "description":"1.3 Test Tool used for documentation purposes.",
   "privacy_level":"public",
   "oidc_initiation_url":"https://your.oidc_initiation_url",
   "target_link_uri":"https://your.target_link_uri",
   "scopes":[
       "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
       "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
    ],
   "extensions":[
      {
         "domain":"thebesttool.com",
         "tool_id":"the-best-tool",
         "platform":"canvas.instructure.com",
         "settings":{
            "text":"Launch The Best Tool",
            "icon_url":"https://some.icon.url/tool-level.png",
            "selection_height": 800,
            "selection_width": 800,
            "placements":[
               {
                  "text":"User Navigation Placement",
                  "enabled":true,
                  "icon_url":"https://some.icon.url/my_dashboard.png",
                  "placement":"user_navigation",
                  "message_type":"LtiResourceLinkRequest",
                  "target_link_uri":"https://your.target_link_uri/my_dashboard",
                  "canvas_icon_class":"icon-lti",
                  "custom_fields":{
                     "foo":"$Canvas.user.id"
                   }
               },
               {
                  "text":"Editor Button Placement",
                  "enabled":true,
                  "icon_url":"https://some.icon.url/editor_tool.png",
                  "placement":"editor_button",
                  "message_type":"LtiDeepLinkingRequest",
                  "target_link_uri":"https://your.target_link_uri/content_selector",
                  "selection_height": 500,
                  "selection_width": 500
               }
            ]
         }
      }
   ],
   "public_jwk":{
      "kty":"RSA",
      "alg":"RS256",
      "e":"AQAB",
      "kid":"8f796169-0ac4-48a3-a202-fa4f3d814fcd",
      "n":"nZD7QWmIwj-3N_RZ1qJjX6CdibU87y2l02yMay4KunambalP9g0fU9yZLwLX9WYJINcXZDUf6QeZ-SSbblET-h8Q4OvfSQ7iuu0WqcvBGy8M0qoZ7I-NiChw8dyybMJHgpiP_AyxpCQnp3bQ6829kb3fopbb4cAkOilwVRBYPhRLboXma0cwcllJHPLvMp1oGa7Ad8osmmJhXhM9qdFFASg_OCQdPnYVzp8gOFeOGwlXfSFEgt5vgeU25E-ycUOREcnP7BnMUk7wpwYqlE537LWGOV5z_1Dqcqc9LmN-z4HmNV7b23QZW4_mzKIOY4IqjmnUGgLU9ycFj5YGDCts7Q",
      "use":"sig"
   },
   "custom_fields":{
      "bar":"$Canvas.user.sisid"
   }

}
```

[ims_lti_1.3_core_spec]: https://www.imsglobal.org/spec/lti/v1p3/
[ims_lti_1.3_impl_guide]: https://www.imsglobal.org/spec/lti/v1p3/impl/
[ims_sec]: https://www.imsglobal.org/spec/security/v1p0/
[canvas_lti]: https://canvas.instructure.com/doc/api/file.lti_dev_key_config.html
[oauth_playground]: https://oauth.com/playground/
[oidc_core]: https://openid.net/specs/openid-connect-core-1_0.html
[canvas_lti_adv_auth]: https://canvas.instructure.com/doc/api/file.oauth.html#developer-key-setup
[canvas_oauth_login]: https://canvas.instructure.com/doc/api/file.oauth_endpoints.html#post-login-oauth2-token
