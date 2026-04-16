import numpy as np
from keras.models import Model
from keras.layers import Input, Dense

def train_autoencoder(X_train, y_train):
    X_train_benign = X_train[y_train == 0]

    input_dim = X_train.shape[1]

    input_layer = Input(shape=(input_dim,))
    encoded = Dense(32, activation='relu')(input_layer)
    encoded = Dense(16, activation='relu')(encoded)

    decoded = Dense(32, activation='relu')(encoded)
    decoded = Dense(input_dim, activation='linear')(decoded)

    autoencoder = Model(inputs=input_layer, outputs=decoded)
    autoencoder.compile(optimizer='adam', loss='mse')

    autoencoder.fit(
        X_train_benign, X_train_benign,
        epochs=10,
        batch_size=256,
        shuffle=True,
        verbose=0
    )

    return autoencoder


def predict_autoencoder(model, X):
    reconstructions = model.predict(X)
    mse = np.mean(np.power(X - reconstructions, 2), axis=1)

    threshold = np.percentile(mse, 95)
    return [1 if x > threshold else 0 for x in mse]