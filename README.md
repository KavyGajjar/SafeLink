# SafeLink

SafeLink is a machine learning web application that detects whether a URL is safe or malicious. The application uses a trained Scikit-learn model and provides predictions through a Flask-based web interface.

## Features

- Detects phishing and malicious URLs
- Machine learning-based prediction
- Simple and responsive web interface
- Fast URL classification
- Easy to run locally

## Technologies Used

- Python
- Flask
- Scikit-learn
- HTML
- CSS
- JavaScript

## Project Structure

```
SafeLink/
│── app.py
│── feature_extractor.py
│── train_model.py
│── model.pkl
│── urlset.csv
│── requirements.txt
│── templates/
│   └── index.html
```

## Installation

Clone the repository:

```bash
git clone https://github.com/KavyGajjar/SafeLink.git
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open your browser and visit:

```
http://127.0.0.1:5000
```

## Future Improvements

- Deep learning-based URL detection
- Browser extension
- REST API support
- Real-time threat intelligence integration
- Improved feature engineering

## Author

Kavy Gajjar

B.Tech Computer Science and Engineering

Silver Oak University