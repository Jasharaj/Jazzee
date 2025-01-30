# Cloud Scanner

A web application for scanning and analyzing cloud resources.

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd cloud-scanner/backend

2. Create a virtual environment (recommended):
   
  python -m venv venv
  source venv/bin/activate  # On Windows use: venv\Scripts\activate

3. Install dependencies:

   pip install -r requirements.txt

4. Set up environment variables:
   
  Copy .env.example to .env
  Fill in your configuration values in .env

5. Start the backend server:

  uvicorn app.main:app --reload
  
  The backend server will start on http://localhost:8000

###Frontend Setup

1. Navigate to the frontend director:

   cd cloud-scanner/frontend

2. Install dependencies:

   npm install

3. Start the development server:

   npm run dev

   The frontend will be available at http://localhost:3000

###Accessing the Application
Once both servers are running:

  Frontend: http://localhost:3000
  Backend API: http://localhost:8000
  API Documentation: http://localhost:8000/docs


This README provides the essential information needed to get the application up and running. You can copy this content and add it to your GitHub repository.

