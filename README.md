# GuardianX

This project was created by team MHAF as a part of our University project, where we're focusing on a secure DevSecOps deployment.
#MHAF: M = Med Ali Mellah, H = Hyba Ayeshi, A = Ala Eddine Largat, F = Fyras Mabrouki

## Project Name: DevSecOps Security Suite

### Description

DevSecOps Security Suite focuses on embedding security into every phase of the software development lifecycle. This project utilizes Terraform to set up and manage infrastructure on AWS, integrates multiple security tools into a Jenkins CI/CD pipeline, and ensures compliance and security through automated checks and balances.

### Key Features

- Infrastructure as Code (IaC) with Terraform for automated and consistent environment setups.
- Code quality and security analysis using SonarQube.
- Comprehensive dependency management and security scanning with OWASP Dependency-Check.
- Container security assessments using Trivy.
- Real-time dynamic security testing with OWASP ZAP.
- Enhanced security for open-source dependencies with Snyk.
- Secure handling of secrets and sensitive data with HashiCorp Vault.
- Detailed reporting and alerts for security vulnerabilities.

Here's a comprehensive DevSecOps project that integrates multiple scanning and security testing tools into a single CI/CD pipeline. This project leverages various tools to ensure robust security practices throughout the software development lifecycle.

### Project Overview

Objective: To create a secure CI/CD pipeline that integrates static code analysis, dependency scanning, container security, and dynamic application security testing (DAST).

### Tools Used

- Jenkins for CI/CD orchestration
- SonarQube for static code analysis
- OWASP Dependency-Check for dependency vulnerability scanning
- Trivy for container image scanning
- OWASP ZAP for dynamic application security testing (DAST)
- Snyk for open-source dependency and container security
- HashiCorp Vault for secrets management

## GuardianX

<div align="center">
<a href="">
<img src="/img_scans/iconn.jpg" alt="Logo" width="80" height="80">
</a>
<h3 align="center">GuardianX</h3>
<p align="center">
A comprehensive web URL vulnerability scanner.
<br/>
<a href="">View Demo</a>  
·
<a href="">Report Bug</a>
·
<a href="">Request Feature</a>
</p>
</div>

### About The Project

![Product Screenshot](/img_scans/home.jpeg)

__GuardianX__ is a sophisticated web application designed to enhance your cybersecurity measures by providing an extensive URL analysis tool. Integrating with VirusTotal, it scans URLs for vulnerabilities and potential threats, ensuring a safer browsing experience for users.

### Built With

GuardianX utilizes several key frameworks and libraries to deliver a robust and feature-rich application:

- [Flask](https://flask.palletsprojects.com/)
- [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/)
- [Flask-Login](https://flask-login.readthedocs.io/)
- [Authlib](https://docs.authlib.org/)
- [Auth0](https://auth0.com/)
- [Jinja2](https://jinja.palletsprojects.com/)
- [SQLite](https://www.sqlite.org/)
- [jQuery](https://jquery.com/)
- [Bootstrap](https://getbootstrap.com/)
- [Werkzeug](https://pypi.org/project/Werkzeug/)
- [Requests](https://pypi.org/project/requests/)

## Getting Started

To get a local copy up and running, follow these simple steps:

### Prerequisites

Ensure you have the following tools installed before proceeding with the installation:

- **Python**

Ensure Python is installed on your system. You can download and install Python from [the official website](https://www.python.org/downloads/).

### Installation

Follow these steps to install and set up the GuardianX application:

1. **Get a free API Key:** Visit [VirusTotal](https://www.virustotal.com) to obtain a free API key.

2. **Clone the repository:** Use Git to clone the GuardianX repository to your local machine.
   ```bash
   git clone https://github.com/mella7/GuardianX.git
3. **Install dependencies:** Navigate to the project directory and install the required Python packages using pip.
   ```bash
   cd GuardianX
   pip install -r requirements.txt
4. **Set up environment variables:** Create a .env file in the project directory and add your API keys and other sensitive information.
   ```bash  
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   AUTH0_CLIENT_ID=your_auth0_client_id
   AUTH0_CLIENT_SECRET=your_auth0_client_secret
   AUTH0_DOMAIN=your_auth0_domain
   SECRET_KEY=your_secret_key
   AUTH0_CALLBACK_URL=your_auth0_callback_url
5. **Run the application:** Start the Flask development server to run the GuardianX application.
   ```bash
   python app.py
6. **Access the application:** Open your web browser and navigate to http://localhost:5000 to access the GuardianX application.

 
