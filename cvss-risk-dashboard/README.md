# CVSS Score Prediction & Risk Assessment Dashboard

A professional and interactive web interface for predicting CVSS (Common Vulnerability Scoring System) scores and visualizing risk assessments. This project uses a weighted model to classify security vulnerabilities based on various metrics.

## Features

### CVSS Score Prediction Page
- Input form for vulnerability metrics (CWE code, access vector, authentication, etc.)
- Dynamic calculation of CVSS base scores
- Visual representation of risk levels
- Weighted risk classification model

### Risk Assessment Dashboard
- Visual overview of vulnerability risk profile
- Distribution charts for risk levels and impact metrics
- Timeline view of CVSS scores
- Detailed vulnerability assessment table
- Export functionality for risk reports
- Comprehensive risk classification details

## Risk Classification Model

The Risk Classification Score (RCS) is computed using a weighted model:
- Exploitability Metrics (Access Vector, Complexity, Authentication): 30% weight
- Impact Metrics (Confidentiality, Integrity, Availability): 50% weight
- Vulnerability Summary (NLP-based analysis): 20% weight

Based on this weighted score, risks are classified as:
- Low Risk: RCS < 3.5
- Medium Risk: 3.5 ≤ RCS < 6.5
- High Risk: 6.5 ≤ RCS < 8.5
- Critical Risk: RCS ≥ 8.5

## Technical Details

This project is implemented using:
- HTML5 for structure
- CSS3 for styling
- Vanilla JavaScript for functionality
- Chart.js for data visualization
- jsPDF for report generation

## File Structure

