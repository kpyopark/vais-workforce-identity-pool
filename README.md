# Facebook Login & Search Demo with Google Cloud Platform

## Overview

This project demonstrates how to integrate Facebook login with Google Cloud Platform (GCP) for authentication and authorization. It allows users to log in with their Facebook account, retrieve a GCP token, and use that token to interact with GCP services, specifically with the search widget.

## Features

- **Facebook Login:** Users can log in using their Facebook accounts.
- **GCP Token Retrieval:** Upon successful Facebook login, the application retrieves a GCP token using the Facebook token.
- **Search Widget Integration:** The application integrates with a Google Search Widget, enabling search functionality using the obtained GCP token.
- **Dynamic JWK Generation:** Generates a RSA key pair and provides a JWK (JSON Web Key) for GCP workforce pool provider configuration.
- **JWT Generation:** Generates a JWT token with Facebook user information for use in GCP token exchange.
- **Environment Variable Configuration:** Uses `.env` file for managing sensitive configuration values.
- **Dynamic index.html Configuration** Replaces placeholder values in `index.html.template` with the actual values in the `.env` file, and saves the result to `index.html`

## Prerequisites

- **Python 3.6+**
- **pip**
- **Google Cloud Platform (GCP) Account**
- **Facebook Developer Account**

## Setup

### 1. Clone the Repository
```bash
git clone <repository_url>
cd <repository_directory>
```

### 2. Install Dependencies
```bash
pip install Flask requests python-dotenv pyjwt cryptography
```

### 3. Configure Environment Variables

- Create a `.env` file in the root directory.
- Add the following environment variables:

```
WORKFORCE_POOL_ID="your_gcp_workforce_pool_id"
WORKFORCE_PROVIDER_ID="your_gcp_workforce_provider_id"
PROJECT_NUMBER="your_gcp_project_number"
JWT_SECRET_KEY="your_jwt_secret_key"
SEARCH_CONFIG_ID="your_gcp_gen_app_builder_search_config_id"
FACEBOOK_APP_ID="your_facebook_app_id"
```

- Replace the placeholders with your actual values.
    - **WORKFORCE_POOL_ID**: Your GCP Workforce Pool ID.
    - **WORKFORCE_PROVIDER_ID**: Your GCP Workforce Provider ID.
    - **PROJECT_NUMBER**: Your GCP Project Number.
    - **JWT_SECRET_KEY**: Secret key for JWT signing.
    - **SEARCH_CONFIG_ID**: Your Google Generative AI App Builder Search Config ID.
    - **FACEBOOK_APP_ID**: Your Facebook App ID.

### 4. Generate RSA Key Pair and JWK
- The application automatically generates an RSA key pair when it starts.
- The Public JWK is printed to the console and exposed at `/jwk.json`.
- Copy and paste the JWK to your workforce pool provider configuration.

### 5. Configure Facebook App Settings
- In your Facebook app dashboard, add localhost (e.g., `http://localhost:5000`) as a valid OAuth redirect URI.

### 6. Modify static/index.html.template
-  The application will replace SEARCH_CONFIG_ID, FACEBOOK_APP_ID placeholders with the actual values of envrionment variables.

## Running the Application

```bash
python app.py
```

- Access the application at `http://localhost:5000`.
- Click the "Facebook으로 로그인" button to log in with your Facebook account.
- If login is successful, user information will be displayed, and the search widget will appear.
- Use the search bar to execute searches.

## API Endpoints

- **`GET /`**: Serves the main HTML page with the Facebook login button and search widget.
- **`GET /jwk.json`**: Provides the public JWK for GCP configuration.
- **`POST /get_gcp_token`**: Accepts a Facebook token and returns a GCP token.

## Technologies

- **Python**
- **Flask**
- **Requests**
- **PyJWT**
- **python-dotenv**
- **Cryptography**
- **Facebook JavaScript SDK**

## Important Notes

- The application prints sensitive information (like JWT) to the console for demonstration purposes. In production, logging sensitive information should be avoided.
- Ensure that the necessary GCP APIs are enabled and that the workforce pool provider is correctly configured.

## Next Steps

- Implement error handling for all external API calls.
- Securely store the JWT secret key and RSA private key.
- Add user interface improvements and additional search features.

## Contributing

Contributions to this project are welcome. Please submit a pull request with your proposed changes.

## License

This project is licensed under the [MIT License](LICENSE).
