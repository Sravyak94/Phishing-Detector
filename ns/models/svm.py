import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn import svm
import joblib
import os

#importing the dataset
dataset = pd.read_csv("./models/dataset/dataset.csv")
dataset = dataset.drop('index', 1) #removing unwanted column

x = dataset.iloc[ : , :-1].values
y = dataset.iloc[:, -1:].values

#spliting the dataset into training set and test set
from sklearn.model_selection import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x,y,test_size = 0.25, random_state =0 )

#----------------applying grid search to find best performing parameters 
from sklearn.model_selection import GridSearchCV
parameters = [{'n_estimators': [100, 700],
    'max_features': ['sqrt', 'log2'],
    'criterion' :['gini', 'entropy']}]

#fitting svm
classifier = svm.SVC(kernel = 'rbf')
classifier.fit(x_train, y_train.ravel())

#predicting the tests set result
y_pred = classifier.predict(x_test)

#confusion matrix
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
print(cm)
