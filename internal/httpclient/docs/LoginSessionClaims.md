# LoginSessionClaims

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Acr** | Pointer to **string** | ACR is the Authentication Context Class Reference value of the login session. | [optional] 
**Amr** | Pointer to **[]string** | AMR is the Authentication Methods References value of the login session. | [optional] 
**AuthTime** | Pointer to **int64** | AuthTime is the time (in seconds since the Unix epoch) when the end-user authenticated. | [optional] 
**Birthdate** | Pointer to **interface{}** | Birthdate is the birthdate claim set in the consent session&#39;s ID token data. | [optional] 
**FamilyName** | Pointer to **interface{}** | FamilyName is the family_name claim set in the consent session&#39;s ID token data. | [optional] 
**GivenName** | Pointer to **interface{}** | GivenName is the given_name claim set in the consent session&#39;s ID token data. | [optional] 
**PhoneNumber** | Pointer to **interface{}** | PhoneNumber is the phone_number claim set in the consent session&#39;s ID token data. | [optional] 
**PhoneNumberVerified** | Pointer to **interface{}** | PhoneNumberVerified is the phone_number_verified claim set in the consent session&#39;s ID token data. | [optional] 
**Subject** | Pointer to **string** | Subject is the subject of the login session. | [optional] 

## Methods

### NewLoginSessionClaims

`func NewLoginSessionClaims() *LoginSessionClaims`

NewLoginSessionClaims instantiates a new LoginSessionClaims object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewLoginSessionClaimsWithDefaults

`func NewLoginSessionClaimsWithDefaults() *LoginSessionClaims`

NewLoginSessionClaimsWithDefaults instantiates a new LoginSessionClaims object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAcr

`func (o *LoginSessionClaims) GetAcr() string`

GetAcr returns the Acr field if non-nil, zero value otherwise.

### GetAcrOk

`func (o *LoginSessionClaims) GetAcrOk() (*string, bool)`

GetAcrOk returns a tuple with the Acr field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAcr

`func (o *LoginSessionClaims) SetAcr(v string)`

SetAcr sets Acr field to given value.

### HasAcr

`func (o *LoginSessionClaims) HasAcr() bool`

HasAcr returns a boolean if a field has been set.

### GetAmr

`func (o *LoginSessionClaims) GetAmr() []string`

GetAmr returns the Amr field if non-nil, zero value otherwise.

### GetAmrOk

`func (o *LoginSessionClaims) GetAmrOk() (*[]string, bool)`

GetAmrOk returns a tuple with the Amr field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAmr

`func (o *LoginSessionClaims) SetAmr(v []string)`

SetAmr sets Amr field to given value.

### HasAmr

`func (o *LoginSessionClaims) HasAmr() bool`

HasAmr returns a boolean if a field has been set.

### GetAuthTime

`func (o *LoginSessionClaims) GetAuthTime() int64`

GetAuthTime returns the AuthTime field if non-nil, zero value otherwise.

### GetAuthTimeOk

`func (o *LoginSessionClaims) GetAuthTimeOk() (*int64, bool)`

GetAuthTimeOk returns a tuple with the AuthTime field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthTime

`func (o *LoginSessionClaims) SetAuthTime(v int64)`

SetAuthTime sets AuthTime field to given value.

### HasAuthTime

`func (o *LoginSessionClaims) HasAuthTime() bool`

HasAuthTime returns a boolean if a field has been set.

### GetBirthdate

`func (o *LoginSessionClaims) GetBirthdate() interface{}`

GetBirthdate returns the Birthdate field if non-nil, zero value otherwise.

### GetBirthdateOk

`func (o *LoginSessionClaims) GetBirthdateOk() (*interface{}, bool)`

GetBirthdateOk returns a tuple with the Birthdate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBirthdate

`func (o *LoginSessionClaims) SetBirthdate(v interface{})`

SetBirthdate sets Birthdate field to given value.

### HasBirthdate

`func (o *LoginSessionClaims) HasBirthdate() bool`

HasBirthdate returns a boolean if a field has been set.

### SetBirthdateNil

`func (o *LoginSessionClaims) SetBirthdateNil(b bool)`

 SetBirthdateNil sets the value for Birthdate to be an explicit nil

### UnsetBirthdate
`func (o *LoginSessionClaims) UnsetBirthdate()`

UnsetBirthdate ensures that no value is present for Birthdate, not even an explicit nil
### GetFamilyName

`func (o *LoginSessionClaims) GetFamilyName() interface{}`

GetFamilyName returns the FamilyName field if non-nil, zero value otherwise.

### GetFamilyNameOk

`func (o *LoginSessionClaims) GetFamilyNameOk() (*interface{}, bool)`

GetFamilyNameOk returns a tuple with the FamilyName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFamilyName

`func (o *LoginSessionClaims) SetFamilyName(v interface{})`

SetFamilyName sets FamilyName field to given value.

### HasFamilyName

`func (o *LoginSessionClaims) HasFamilyName() bool`

HasFamilyName returns a boolean if a field has been set.

### SetFamilyNameNil

`func (o *LoginSessionClaims) SetFamilyNameNil(b bool)`

 SetFamilyNameNil sets the value for FamilyName to be an explicit nil

### UnsetFamilyName
`func (o *LoginSessionClaims) UnsetFamilyName()`

UnsetFamilyName ensures that no value is present for FamilyName, not even an explicit nil
### GetGivenName

`func (o *LoginSessionClaims) GetGivenName() interface{}`

GetGivenName returns the GivenName field if non-nil, zero value otherwise.

### GetGivenNameOk

`func (o *LoginSessionClaims) GetGivenNameOk() (*interface{}, bool)`

GetGivenNameOk returns a tuple with the GivenName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGivenName

`func (o *LoginSessionClaims) SetGivenName(v interface{})`

SetGivenName sets GivenName field to given value.

### HasGivenName

`func (o *LoginSessionClaims) HasGivenName() bool`

HasGivenName returns a boolean if a field has been set.

### SetGivenNameNil

`func (o *LoginSessionClaims) SetGivenNameNil(b bool)`

 SetGivenNameNil sets the value for GivenName to be an explicit nil

### UnsetGivenName
`func (o *LoginSessionClaims) UnsetGivenName()`

UnsetGivenName ensures that no value is present for GivenName, not even an explicit nil

### GetPhoneNumber

`func (o *LoginSessionClaims) GetPhoneNumber() interface{}`

GetPhoneNumber returns the PhoneNumber field if non-nil, zero value otherwise.

### GetPhoneNumberOk

`func (o *LoginSessionClaims) GetPhoneNumberOk() (*interface{}, bool)`

GetPhoneNumberOk returns a tuple with the PhoneNumber field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPhoneNumber

`func (o *LoginSessionClaims) SetPhoneNumber(v interface{})`

SetPhoneNumber sets PhoneNumber field to given value.

### HasPhoneNumber

`func (o *LoginSessionClaims) HasPhoneNumber() bool`

HasPhoneNumber returns a boolean if a field has been set.

### SetPhoneNumberNil

`func (o *LoginSessionClaims) SetPhoneNumberNil(b bool)`

 SetPhoneNumberNil sets the value for PhoneNumber to be an explicit nil

### UnsetPhoneNumber
`func (o *LoginSessionClaims) UnsetPhoneNumber()`

UnsetPhoneNumber ensures that no value is present for PhoneNumber, not even an explicit nil

### GetPhoneNumberVerified

`func (o *LoginSessionClaims) GetPhoneNumberVerified() interface{}`

GetPhoneNumberVerified returns the PhoneNumberVerified field if non-nil, zero value otherwise.

### GetPhoneNumberVerifiedOk

`func (o *LoginSessionClaims) GetPhoneNumberVerifiedOk() (*interface{}, bool)`

GetPhoneNumberVerifiedOk returns a tuple with the PhoneNumberVerified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPhoneNumberVerified

`func (o *LoginSessionClaims) SetPhoneNumberVerified(v interface{})`

SetPhoneNumberVerified sets PhoneNumberVerified field to given value.

### HasPhoneNumberVerified

`func (o *LoginSessionClaims) HasPhoneNumberVerified() bool`

HasPhoneNumberVerified returns a boolean if a field has been set.

### SetPhoneNumberVerifiedNil

`func (o *LoginSessionClaims) SetPhoneNumberVerifiedNil(b bool)`

 SetPhoneNumberVerifiedNil sets the value for PhoneNumberVerified to be an explicit nil

### UnsetPhoneNumberVerified
`func (o *LoginSessionClaims) UnsetPhoneNumberVerified()`

UnsetPhoneNumberVerified ensures that no value is present for PhoneNumberVerified, not even an explicit nil

### GetSubject

`func (o *LoginSessionClaims) GetSubject() string`

GetSubject returns the Subject field if non-nil, zero value otherwise.

### GetSubjectOk

`func (o *LoginSessionClaims) GetSubjectOk() (*string, bool)`

GetSubjectOk returns a tuple with the Subject field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubject

`func (o *LoginSessionClaims) SetSubject(v string)`

SetSubject sets Subject field to given value.

### HasSubject

`func (o *LoginSessionClaims) HasSubject() bool`

HasSubject returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


