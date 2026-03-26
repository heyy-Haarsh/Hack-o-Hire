import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib
import os

def train_model():
    dataset_path = 'hackathon/ML/train_dataset.csv'
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        return

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    
    # Drop rows where industry is NaN
    df = df.dropna(subset=['industry'])
    
    # Fill NaN values in text columns
    df['pre_text'] = df['pre_text'].fillna('')
    df['post_text'] = df['post_text'].fillna('')
    
    # Combine pre_text and post_text
    df['text'] = df['pre_text'] + " " + df['post_text']
    
    X = df['text']
    y = df['industry']
    
    print(f"Dataset loaded. Total samples: {len(df)}")
    print(f"Unique industries: {df['industry'].unique()}")
    
    # Create pipeline
    model_pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(stop_words='english', max_features=10000)),
        ('clf', LogisticRegression(max_iter=1000))
    ])
    
    print("Fitting model...")
    model_pipeline.fit(X, y)
    
    # Save the model
    save_dir = os.path.join('src', 'models')
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
        
    save_path = os.path.join(save_dir, 'content_classifier.joblib')
    joblib.dump(model_pipeline, save_path)
    print(f"Model successfully saved to {save_path}")

if __name__ == "__main__":
    train_model()
