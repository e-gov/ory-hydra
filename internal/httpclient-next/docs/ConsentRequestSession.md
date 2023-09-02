# ConsentRequestSession

## Properties

| Name                          | Type                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                | Notes      |
| ----------------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| **AccessToken**               | Pointer to **interface{}** | AccessToken sets session data for the access and refresh token, as well as any future tokens issued by the refresh grant. Keep in mind that this data will be available to anyone performing OAuth 2.0 Challenge Introspection. If only your services can perform OAuth 2.0 Challenge Introspection, this is usually fine. But if third parties can access that endpoint as well, sensitive data from the session might be exposed to them. Use with care! | [optional] |
| **ConsentRememberFor**        | Pointer to **int64**       |                                                                                                                                                                                                                                                                                                                                                                                                                                                            | [optional] |
| **IdToken**                   | Pointer to **interface{}** | IDToken sets session data for the OpenID Connect ID token. Keep in mind that the session&#39;id payloads are readable by anyone that has access to the ID Challenge. Use with care!                                                                                                                                                                                                                                                                        | [optional] |
| **RefreshConsentRememberFor** | Pointer to **bool**        | Extends consent remember for if true                                                                                                                                                                                                                                                                                                                                                                                                                       | [optional] |
| **RefreshRememberFor**        | Pointer to **bool**        | Extends session remember for if true                                                                                                                                                                                                                                                                                                                                                                                                                       | [optional] |
| **RememberFor**               | Pointer to **int64**       |                                                                                                                                                                                                                                                                                                                                                                                                                                                            | [optional] |

## Methods

### NewConsentRequestSession

`func NewConsentRequestSession() *ConsentRequestSession`

NewConsentRequestSession instantiates a new ConsentRequestSession object This
constructor will assign default values to properties that have it defined, and
makes sure properties required by API are set, but the set of arguments will
change when the set of required properties is changed

### NewConsentRequestSessionWithDefaults

`func NewConsentRequestSessionWithDefaults() *ConsentRequestSession`

NewConsentRequestSessionWithDefaults instantiates a new ConsentRequestSession
object This constructor will only assign default values to properties that have
it defined, but it doesn't guarantee that properties required by API are set

### GetAccessToken

`func (o *ConsentRequestSession) GetAccessToken() interface{}`

GetAccessToken returns the AccessToken field if non-nil, zero value otherwise.

### GetAccessTokenOk

`func (o *ConsentRequestSession) GetAccessTokenOk() (*interface{}, bool)`

GetAccessTokenOk returns a tuple with the AccessToken field if it's non-nil,
zero value otherwise and a boolean to check if the value has been set.

### SetAccessToken

`func (o *ConsentRequestSession) SetAccessToken(v interface{})`

SetAccessToken sets AccessToken field to given value.

### HasAccessToken

`func (o *ConsentRequestSession) HasAccessToken() bool`

HasAccessToken returns a boolean if a field has been set.

### SetAccessTokenNil

`func (o *ConsentRequestSession) SetAccessTokenNil(b bool)`

SetAccessTokenNil sets the value for AccessToken to be an explicit nil

### UnsetAccessToken

`func (o *ConsentRequestSession) UnsetAccessToken()`

UnsetAccessToken ensures that no value is present for AccessToken, not even an
explicit nil

### GetConsentRememberFor

`func (o *ConsentRequestSession) GetConsentRememberFor() int64`

GetConsentRememberFor returns the ConsentRememberFor field if non-nil, zero
value otherwise.

### GetConsentRememberForOk

`func (o *ConsentRequestSession) GetConsentRememberForOk() (*int64, bool)`

GetConsentRememberForOk returns a tuple with the ConsentRememberFor field if
it's non-nil, zero value otherwise and a boolean to check if the value has been
set.

### SetConsentRememberFor

`func (o *ConsentRequestSession) SetConsentRememberFor(v int64)`

SetConsentRememberFor sets ConsentRememberFor field to given value.

### HasConsentRememberFor

`func (o *ConsentRequestSession) HasConsentRememberFor() bool`

HasConsentRememberFor returns a boolean if a field has been set.

### GetIdToken

`func (o *ConsentRequestSession) GetIdToken() interface{}`

GetIdToken returns the IdToken field if non-nil, zero value otherwise.

### GetIdTokenOk

`func (o *ConsentRequestSession) GetIdTokenOk() (*interface{}, bool)`

GetIdTokenOk returns a tuple with the IdToken field if it's non-nil, zero value
otherwise and a boolean to check if the value has been set.

### SetIdToken

`func (o *ConsentRequestSession) SetIdToken(v interface{})`

SetIdToken sets IdToken field to given value.

### HasIdToken

`func (o *ConsentRequestSession) HasIdToken() bool`

HasIdToken returns a boolean if a field has been set.

### SetIdTokenNil

`func (o *ConsentRequestSession) SetIdTokenNil(b bool)`

SetIdTokenNil sets the value for IdToken to be an explicit nil

### UnsetIdToken

`func (o *ConsentRequestSession) UnsetIdToken()`

UnsetIdToken ensures that no value is present for IdToken, not even an explicit
nil

### GetRefreshConsentRememberFor

`func (o *ConsentRequestSession) GetRefreshConsentRememberFor() bool`

GetRefreshConsentRememberFor returns the RefreshConsentRememberFor field if
non-nil, zero value otherwise.

### GetRefreshConsentRememberForOk

`func (o *ConsentRequestSession) GetRefreshConsentRememberForOk() (*bool, bool)`

GetRefreshConsentRememberForOk returns a tuple with the
RefreshConsentRememberFor field if it's non-nil, zero value otherwise and a
boolean to check if the value has been set.

### SetRefreshConsentRememberFor

`func (o *ConsentRequestSession) SetRefreshConsentRememberFor(v bool)`

SetRefreshConsentRememberFor sets RefreshConsentRememberFor field to given
value.

### HasRefreshConsentRememberFor

`func (o *ConsentRequestSession) HasRefreshConsentRememberFor() bool`

HasRefreshConsentRememberFor returns a boolean if a field has been set.

### GetRefreshRememberFor

`func (o *ConsentRequestSession) GetRefreshRememberFor() bool`

GetRefreshRememberFor returns the RefreshRememberFor field if non-nil, zero
value otherwise.

### GetRefreshRememberForOk

`func (o *ConsentRequestSession) GetRefreshRememberForOk() (*bool, bool)`

GetRefreshRememberForOk returns a tuple with the RefreshRememberFor field if
it's non-nil, zero value otherwise and a boolean to check if the value has been
set.

### SetRefreshRememberFor

`func (o *ConsentRequestSession) SetRefreshRememberFor(v bool)`

SetRefreshRememberFor sets RefreshRememberFor field to given value.

### HasRefreshRememberFor

`func (o *ConsentRequestSession) HasRefreshRememberFor() bool`

HasRefreshRememberFor returns a boolean if a field has been set.

### GetRememberFor

`func (o *ConsentRequestSession) GetRememberFor() int64`

GetRememberFor returns the RememberFor field if non-nil, zero value otherwise.

### GetRememberForOk

`func (o *ConsentRequestSession) GetRememberForOk() (*int64, bool)`

GetRememberForOk returns a tuple with the RememberFor field if it's non-nil,
zero value otherwise and a boolean to check if the value has been set.

### SetRememberFor

`func (o *ConsentRequestSession) SetRememberFor(v int64)`

SetRememberFor sets RememberFor field to given value.

### HasRememberFor

`func (o *ConsentRequestSession) HasRememberFor() bool`

HasRememberFor returns a boolean if a field has been set.

[[Back to Model list]](../README.md#documentation-for-models)
[[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to README]](../README.md)
