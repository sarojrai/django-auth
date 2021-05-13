# APIs Detail
## 1. Token Generation
* Endpoint : https://{{HOST}}/auth/api/api-token-auth
* Method: POST
* Request:
    * [Sample](/warehouse/authentication/tests/sample_input/api_token_auth.json)
* Field Request
    * Username : Required
    * password : Required
* Response:
    * [Sample Failed](/warehouse/authentication/tests/sample_output/failed_api_token_auth.json)
    * [Sample Success](/warehouse/authentication/tests/sample_output/success_api_token_auth.json)

## 2. User Registration
* Endpoint : https://{{HOST}}/auth/api/user-registration
* Method: POST
* Request:
    * [Sample](/warehouse/authentication/tests/sample_input/user_registeration.json)
* Field Request
    * Username : Required
    * password : Required
    * firstname : Optional
    * lastname : Optional
    * mobile_number : Required
    * confirm_password : Required
    * user_type : Required
* Response:
    * [Sample Failed](/warehouse/authentication/tests/sample_output/failed_user_registeration.json)
    * [Sample Success](/warehouse/authentication/tests/sample_output/success_user_registeration.json)

## 3. User Login
* Endpoints : https://{{HOST}}/auth/api/login
* Method: POST
* Request:
    * [Sample](/warehouse/authentication/tests/sample_input/login.json)
* Field Request
    * Username : Required
    * password : Required
    * request_type : Required
    * app_version : Required
    * device_id : Required
    * device_type : Required
    * app_id : Required
    * id : Required
    * imei : Required
* Response:
    * [Sample Failed](/warehouse/authentication/tests/sample_output/failed_login.json)
    * [Sample Success](/warehouse/authentication/tests/sample_output/success_login.json)

## 4. User Logout
* Endpoints : https://{{HOST}}/auth/api/logout
* Method: GET
* Request:
    * [Sample](/warehouse/authentication/tests/sample_input/logout.json)
* Field Request
    * Username : Required
* Response:
    * [Sample Failed](/warehouse/authentication/tests/sample_output/failed_logout.json)
    * [Sample Success](/warehouse/authentication/tests/sample_output/success_logout.json)

## 5. Get User Details
* Endpoints : https://{{HOST}}/auth/api/get-user-detail/
* Method: GET
* Header: 
    * Authorization : Token 244f8cbd237a3ce4b5ebc3d1e72c945d932b45a0
* Request:
    * [Sample](/warehouse/authentication/tests/sample_input/get_user_detail.json)
* Field Request
    * employee_code : Required
* Response (In JSON):
    * [Sample Failed](/warehouse/authentication/tests/sample_output/failed_get_user_detail.json)
    * [Sample Success](/warehouse/authentication/tests/sample_output/success_get_user_detail.json)

## 6. Update User Status
* Endpoints : https://{{HOST}}/auth/api/update-user-status/
* Method: POST
* Header: 
    * Authorization : Token 244f8cbd237a3ce4b5ebc3d1e72c945d932b45a0
* Request:
    * [Sample](/warehouse/authentication/tests/sample_input/update_user_status.json)
* Field Request
    * employee_code : Required
    * action_type : Required
* Response:
    * [Sample Failed](/warehouse/authentication/tests/failed_update_user_status.json)
    * [Sample Success](/warehouse/authentication/tests/sample_output/success_update_user_status.json)


## 7. Update User Profile
* Endpoints : https://{{HOST}}/auth/api/update-profile/
* Method: POST
* Header: 
    * Authorization : Token 244f8cbd237a3ce4b5ebc3d1e72c945d932b45a0
* Request:
    * [Sample](/warehouse/authentication/tests/sample_input/update_profile.json)
* Field Request
    * employee_code : Required
    * All Other Field : Optional
* Response:
    * [Sample Failed](/warehouse/authentication/tests/failed_update_profile.json)
    * [Sample Success](/warehouse/authentication/tests/sample_output/success_update_profile.json)

## 8. Reset Password
* Endpoints : https://{{HOST}}/auth/api/reset-password
* Method: POST
* Header: 
    * Authorization : Token 244f8cbd237a3ce4b5ebc3d1e72c945d932b45a0
* Request:
    * [Sample](/warehouse/authentication/tests/sample_input/password_reset.json)
* Field Request
    * user_name : Required
    * old_password : Required
    * new_password : Required
    * confirm_password : Required
* Response:
    * [Sample Failed](/warehouse/authentication/tests/failed_password_reset.json)
    * [Sample Failed](/warehouse/authentication/tests/sample_output/success_password_reset.jso  n)