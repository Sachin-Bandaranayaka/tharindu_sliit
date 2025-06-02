# Unified Risk Assessment Backend

A comprehensive risk assessment platform that combines CVSS score prediction, insurance claim fee prediction, and risk framework analysis into a single unified backend with a modern web interface.

## Features

### 🔒 CVSS Score Prediction
- Machine learning-based CVSS score prediction
- Support for vulnerability parameters (CWE, Access Vector, Complexity, etc.)
- Real-time risk level assessment
- Fallback heuristic calculation when ML models are unavailable

### 💰 Insurance Claim Fee Prediction
- AI-powered insurance claim fee estimation
- MongoDB integration for prediction history
- Comprehensive claim data processing
- Historical prediction tracking

### 📊 Risk Framework & Dashboard
- Interactive risk assessment dashboard
- Vulnerability trend analysis
- Risk distribution visualization
- Comprehensive reporting

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone and navigate to the project
cd unified_backend

# Start all services
docker-compose up -d

# Access the application
open http://localhost:5000
```

### Option 2: Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Start MongoDB (if not using Docker)
mongod --dbpath ./data/db

# Run the application
python app.py

# Access the application
open http://localhost:5000
```

## Project Structure

```
unified_backend/
├── app.py                 # Main Flask application
├── cvss_predictor.py      # CVSS prediction module
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Multi-service setup
├── models/               # ML model files
│   ├── cvss_model.pkl
│   ├── tfidf_vectorizer.pkl
│   ├── onehot_encoder.pkl
│   ├── final_claim_fee_predictor.pkl
│   └── feature_names.pkl
├── cvss-risk-dashboard/  # Frontend files
│   ├── index.html        # CVSS prediction page
│   ├── insurance.html    # Insurance claims page
│   ├── dashboard.html    # Risk dashboard
│   ├── risk-framework.html
│   └── static/           # CSS, JS, images
└── templates/            # Additional templates
    ├── dashboard.html
    ├── index.html
    └── history.html
```

## API Endpoints

### CVSS Prediction
- `POST /api/cvss/predict` - Main CVSS prediction endpoint
- `POST /api/cvss/predict-simple` - Alternative CVSS prediction

### Insurance Claims
- `POST /api/insurance/predict` - Predict insurance claim fees
- `GET /api/insurance/history` - Get prediction history

### System
- `GET /api/health` - Health check for all services

## Configuration

### Environment Variables

```bash
# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=False

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/
MONGO_DB_NAME=claim_fee_db

# Model Paths (optional)
MODEL_PATH=./models
```

### MongoDB Setup

The application automatically connects to MongoDB for storing insurance prediction history. If MongoDB is not available, the insurance prediction will still work but without history tracking.

## Model Requirements

Ensure the following model files are present in the `models/` directory:

### CVSS Models
- `cvss_model.pkl` - Trained CVSS prediction model
- `tfidf_vectorizer.pkl` - Text feature vectorizer
- `onehot_encoder.pkl` - Categorical feature encoder

### Insurance Models
- `final_claim_fee_predictor.pkl` - Insurance claim prediction model
- `feature_names.pkl` - Feature names for the insurance model

## Development

### Running in Development Mode

```bash
# Set development environment
export FLASK_ENV=development
export FLASK_DEBUG=True

# Run with auto-reload
python app.py
```

### Adding New Features

1. **New API Endpoints**: Add routes in `app.py`
2. **New ML Models**: Place model files in `models/` directory
3. **Frontend Pages**: Add HTML files in `cvss-risk-dashboard/`
4. **Styling**: Update CSS in `cvss-risk-dashboard/static/style.css`

## Deployment

### Production Deployment with Docker

```bash
# Build and deploy
docker-compose -f docker-compose.yml up -d

# Scale the web service
docker-compose up -d --scale web=3

# View logs
docker-compose logs -f web
```

### Manual Deployment

```bash
# Install production dependencies
pip install -r requirements.txt gunicorn

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

## Monitoring

### Health Checks

The application provides health check endpoints:

```bash
# Check overall system health
curl http://localhost:5000/api/health

# Response example:
{
  "status": "healthy",
  "services": {
    "cvss_predictor": "loaded",
    "insurance_model": "loaded",
    "database": "connected"
  },
  "timestamp": "2024-01-15T10:30:00"
}
```

### Logging

Logs are written to:
- Console output (development)
- `logs/` directory (production)
- Docker logs (containerized deployment)

## Troubleshooting

### Common Issues

1. **Model Loading Errors**
   - Ensure all model files are present in `models/` directory
   - Check file permissions
   - Verify model file integrity

2. **MongoDB Connection Issues**
   - Verify MongoDB is running
   - Check connection string in environment variables
   - Ensure network connectivity

3. **Port Conflicts**
   - Change port in `app.py` or docker-compose.yml
   - Check for other services using port 5000

4. **Memory Issues**
   - ML models require significant RAM
   - Consider using smaller models or increasing system memory
   - Monitor memory usage with `docker stats`

### Performance Optimization

1. **Model Loading**
   - Models are loaded once at startup
   - Consider model caching for better performance

2. **Database Queries**
   - MongoDB queries are optimized for recent predictions
   - Consider adding indexes for better performance

3. **Scaling**
   - Use multiple worker processes with Gunicorn
   - Consider load balancing for high traffic

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Check the troubleshooting section
- Review the API documentation
- Submit issues on the project repository

---

**Note**: This unified backend consolidates multiple risk assessment tools into a single, deployable application. It combines CVSS vulnerability scoring, insurance claim prediction, and risk framework analysis with a modern, responsive web interface.