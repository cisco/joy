'''
 *	
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
'''

from sklearn import linear_model, preprocessing, svm, neighbors
from operator import itemgetter
import numpy as np
import random
import copy

class LogRegClassifier:

    def __init__(self, standardize=True, C=1e5):
        self.standardize = standardize
        self.C = C
        self.is_cv = False
        self.non_zero_params = []

    def train(self, data, labels):
        # learn model for individual flows
        data = np.array(data)
        if self.standardize:
            self.scaler = preprocessing.StandardScaler()
            data = self.scaler.fit_transform(data)
        self.logreg = linear_model.LogisticRegression(penalty='l1')
        self.logreg.fit(data,labels)

    # test function for individual flow
    def test(self, data, labels=None):
        if self.standardize:
            data = self.scaler.transform(data)

        out = list(self.logreg.predict_proba(data))

        if labels == None:
            return out, None, None
        correct = 0
        for i in range(len(out)):
            if self.get_label(out[i]) == labels[i]:
                correct += 1
        acc = correct/float(len(out))

        return out, acc, correct

    def get_label(self, probs):
        return [i for i, j in enumerate(probs) if j == np.amax(probs)][0]

    def get_parameters(self):
        return self.logreg.coef_, self.logreg.intercept_

    def get_num_nonzero_params(self):
        tmp = 0
        for x in self.logreg.coef_[0]:
            if x != 0.0:
                tmp += 1
        return tmp

    def CV(self, data, labels, folds=10):
        self.is_cv = True

        tmp = zip(data,labels)
        random.shuffle(tmp)
        tmp2 = zip(*tmp)
        data = list(tmp2[0])
        labels = list(tmp2[1])

        out_cv = []
        labels_cv = []
        acc_cv = []
        correct_cv = []

        for i in range(folds):
            start = int((i/float(folds))*len(data))
            end = int(((i+1)/float(folds))*len(data))
            train_data = data[0:start]+data[end:]
            train_labels = labels[0:start]+labels[end:]
            test_data = data[start:end]
            test_labels = labels[start:end]
            self.train(train_data,train_labels)
#            self.train(train_data+test_data,train_labels+test_labels)
            out,acc,correct = self.test(test_data,test_labels)
            self.non_zero_params.append(self.get_num_nonzero_params())
            
            out_cv.extend(out)
            acc_cv.append(acc)
            correct_cv.append(correct)
            labels_cv.extend(test_labels)

        return out_cv, acc_cv, correct_cv, labels_cv



