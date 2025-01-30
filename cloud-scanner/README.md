# Cloud Scanner

A robust AWS cloud configuration monitoring tool that identifies security misconfigurations, assesses risks, and provides actionable remediation steps through an intuitive visual interface.

## Features

- Real-time scanning of AWS services (EC2, S3, IAM, RDS)
- Continuous monitoring of security groups, network ACLs, and bucket policies
- Detection of compliance violations against industry standards
- Interactive dashboard with risk-level indicators
- Detailed configuration assessment reports

## Project Structure

```
cloud-scanner/
├── frontend/          # Next.js frontend application
├── backend/           # Python FastAPI backend
├── docker/           # Docker configuration files
└── docs/            # Documentation
```

## Prerequisites

- Python 3.9+
- Node.js 16+
- AWS Account with appropriate permissions
- MongoDB Atlas account

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create .env file:
   ```
   Copy .env.example to .env and fill in your credentials
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start development server:
   ```bash
   npm run dev
   ```

## Development

- Backend API runs on: http://localhost:8000
- Frontend runs on: http://localhost:3000

## License

MIT
