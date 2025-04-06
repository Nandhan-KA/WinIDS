#!/usr/bin/env python
"""
WinIDS Model Training Script

This script trains a neural network model for the WinIDS intrusion detection system.
"""

import os
import sys
import json
import argparse
import logging
import numpy as np
import pandas as pd
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("WinIDS_training.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WinIDS-Training")

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense, Dropout
    from tensorflow.keras.optimizers import Adam
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
except ImportError:
    logger.error("Required libraries not found. Please install tensorflow, scikit-learn, and pandas.")
    sys.exit(1)

def load_dataset(dataset_path):
    """Load dataset from CSV or JSON file.
    
    Args:
        dataset_path: Path to dataset file
        
    Returns:
        features: Features array
        labels: Labels array
    """
    try:
        # Check file extension
        file_ext = os.path.splitext(dataset_path)[1].lower()
        
        if file_ext == '.csv':
            # Load CSV file
            logger.info(f"Loading CSV dataset from {dataset_path}")
            df = pd.read_csv(dataset_path)
            
            # Extract features and labels
            if 'label' in df.columns:
                features = df.drop(['label'], axis=1).values
                labels = df['label'].values
            elif 'attack_type' in df.columns:
                features = df.drop(['attack_type'], axis=1).values
                # Convert attack types to numeric labels
                attack_mapping = {
                    'normal': 0,
                    'dos': 1,
                    'probe': 2,
                    'r2l': 3,
                    'u2r': 4
                }
                labels = df['attack_type'].map(attack_mapping).values
            else:
                # Assume last column is the label
                features = df.iloc[:, :-1].values
                labels = df.iloc[:, -1].values
                
        elif file_ext == '.json':
            # Load JSON file
            logger.info(f"Loading JSON dataset from {dataset_path}")
            with open(dataset_path, 'r') as f:
                data = json.load(f)
                
            # Extract features and labels
            features = []
            labels = []
            
            for entry in data:
                if 'features' in entry:
                    features.append(entry['features'])
                    
                    # Extract label
                    if 'attack_type' in entry:
                        attack_type = entry['attack_type'].lower()
                        if attack_type == 'normal':
                            labels.append(0)
                        elif attack_type == 'dos':
                            labels.append(1)
                        elif attack_type == 'probe':
                            labels.append(2)
                        elif attack_type == 'r2l':
                            labels.append(3)
                        elif attack_type == 'u2r':
                            labels.append(4)
                        else:
                            # Unknown attack type
                            labels.append(0)
                    elif 'is_attack' in entry:
                        # Binary classification
                        labels.append(1 if entry['is_attack'] else 0)
                    else:
                        # Assume normal traffic
                        labels.append(0)
            
            features = np.array(features)
            labels = np.array(labels)
        else:
            raise ValueError(f"Unsupported file extension: {file_ext}")
            
        logger.info(f"Dataset loaded: {features.shape[0]} samples with {features.shape[1]} features")
        return features, labels
        
    except Exception as e:
        logger.error(f"Error loading dataset: {str(e)}")
        sys.exit(1)

def normalize_features(features, save_params=None):
    """Normalize features using StandardScaler.
    
    Args:
        features: Features array
        save_params: Path to save normalization parameters
        
    Returns:
        normalized_features: Normalized features array
        scaler: Fitted StandardScaler
    """
    logger.info("Normalizing features")
    
    # Create scaler
    scaler = StandardScaler()
    
    # Fit and transform features
    normalized_features = scaler.fit_transform(features)
    
    # Save normalization parameters if requested
    if save_params:
        norm_params = {
            'mean': scaler.mean_.tolist(),
            'std': scaler.scale_.tolist()
        }
        
        with open(save_params, 'w') as f:
            json.dump(norm_params, f, indent=2)
            
        logger.info(f"Normalization parameters saved to {save_params}")
    
    return normalized_features, scaler

def create_model(input_dim, num_classes=5):
    """Create a neural network model for intrusion detection.
    
    Args:
        input_dim: Input dimension (number of features)
        num_classes: Number of output classes
        
    Returns:
        model: Compiled Keras model
    """
    logger.info(f"Creating model with {input_dim} input features and {num_classes} classes")
    
    # Create sequential model
    model = Sequential()
    
    # Input layer
    model.add(Dense(128, activation='relu', input_dim=input_dim))
    model.add(Dropout(0.3))
    
    # Hidden layers
    model.add(Dense(64, activation='relu'))
    model.add(Dropout(0.3))
    model.add(Dense(32, activation='relu'))
    model.add(Dropout(0.3))
    
    # Output layer
    if num_classes == 2:
        # Binary classification
        model.add(Dense(1, activation='sigmoid'))
        model.compile(optimizer=Adam(learning_rate=0.001),
                     loss='binary_crossentropy',
                     metrics=['accuracy'])
    else:
        # Multi-class classification
        model.add(Dense(num_classes, activation='softmax'))
        model.compile(optimizer=Adam(learning_rate=0.001),
                     loss='sparse_categorical_crossentropy',
                     metrics=['accuracy'])
    
    # Print model summary
    model.summary()
    
    return model

def train_model(model, X_train, y_train, X_val, y_val, batch_size=32, epochs=20):
    """Train the model.
    
    Args:
        model: Keras model
        X_train: Training features
        y_train: Training labels
        X_val: Validation features
        y_val: Validation labels
        batch_size: Batch size
        epochs: Number of epochs
        
    Returns:
        history: Training history
    """
    logger.info(f"Training model with {X_train.shape[0]} samples for {epochs} epochs")
    
    # Create early stopping callback
    early_stopping = tf.keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=5,
        restore_best_weights=True
    )
    
    # Train model
    history = model.fit(
        X_train, y_train,
        batch_size=batch_size,
        epochs=epochs,
        validation_data=(X_val, y_val),
        callbacks=[early_stopping],
        verbose=1
    )
    
    # Evaluate model
    loss, accuracy = model.evaluate(X_val, y_val, verbose=0)
    logger.info(f"Validation accuracy: {accuracy:.4f}")
    
    return history

def save_model(model, model_path):
    """Save model to disk.
    
    Args:
        model: Keras model
        model_path: Path to save model
    """
    logger.info(f"Saving model to {model_path}")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Save model
    model.save(model_path)
    
    logger.info("Model saved successfully")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="WinIDS Model Training Script")
    
    parser.add_argument("--dataset", type=str, required=True,
                      help="Path to dataset file (CSV or JSON)")
    parser.add_argument("--model-output", type=str, default="models/best_fast_model.h5",
                      help="Path to save trained model")
    parser.add_argument("--norm-params", type=str, default="models/normalization_params.json",
                      help="Path to save normalization parameters")
    parser.add_argument("--binary", action="store_true",
                      help="Train a binary classifier (attack/normal) instead of multi-class")
    parser.add_argument("--epochs", type=int, default=20,
                      help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=32,
                      help="Batch size for training")
    parser.add_argument("--test-split", type=float, default=0.2,
                      help="Fraction of data to use for validation")
    
    return parser.parse_args()

def main():
    """Main entry point."""
    # Parse command line arguments
    args = parse_args()
    
    # Load dataset
    features, labels = load_dataset(args.dataset)
    
    # Determine number of classes
    if args.binary:
        num_classes = 2
        # Convert multi-class labels to binary (attack/normal)
        labels = (labels > 0).astype(int)
    else:
        num_classes = len(np.unique(labels))
        
    logger.info(f"Number of classes: {num_classes}")
    
    # Split dataset
    X_train, X_val, y_train, y_val = train_test_split(
        features, labels, test_size=args.test_split, random_state=42, stratify=labels
    )
    
    # Normalize features
    X_train_norm, scaler = normalize_features(X_train, save_params=args.norm_params)
    X_val_norm = scaler.transform(X_val)
    
    # Create model
    model = create_model(X_train_norm.shape[1], num_classes=num_classes)
    
    # Train model
    history = train_model(
        model, X_train_norm, y_train, X_val_norm, y_val,
        batch_size=args.batch_size, epochs=args.epochs
    )
    
    # Save model
    save_model(model, args.model_output)
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 