import os
import traceback

import weka.core.jvm as jvm
import sys

from weka.core.converters import Loader

from weka.core.classes import Random
from weka.core.dataset import Instances
from weka.classifiers import Classifier, Evaluation
from weka.filters import Filter

from weka.core.dataset import Attribute

jvm.start()

print()
data_dir = "Arff_Editor_Outputs/"
loader = Loader(classname="weka.core.converters.ArffLoader")

if(len(sys.argv) < 2):
    print("Please pass in arff file path when executing")
    exit()

arffFileName = sys.argv[1]

data = loader.load_file(arffFileName)
data.class_is_last()
data.delete_attribute(0) #delete source IP attribute
data.delete_attribute(1) #delete destination IP attribute

#nominalAttr = Attribute.create_nominal("class", "{yes, no}")
#data.delete_last_attribute()
#data.insert_attribute(nominalAttr, 0)
#data.class_is_first()

#print(data)

classifier = Classifier(classname="weka.classifiers.trees.RandomForest")
classifier.options = ['-P', '100', '-I', '100', '-num-slots', '1', '-K', '0', '-M', '1.0', '-V', '0.001', '-S', '1']

folds = 10
seed = 1
rnd = Random(seed)
rand_data = Instances.copy_instances(data)
rand_data.randomize(rnd)
if rand_data.class_attribute.is_nominal:
    rand_data.stratify(folds)

progress = 0

predicted_data = None
evaluation = Evaluation(rand_data)
for i in range(folds):
    print(progress)
    progress = progress + 1

    train = rand_data.train_cv(folds, i)
    # the above code is used by the StratifiedRemoveFolds filter,
    # the following code is used by the Explorer/Experimenter
    # train = rand_data.train_cv(folds, i, rnd)
    test = rand_data.test_cv(folds, i)

    # build and evaluate classifier
    cls = Classifier.make_copy(classifier)
    cls.build_classifier(train)
    evaluation.test_model(cls, test)

    # add predictions
    addcls = Filter(
        classname="weka.filters.supervised.attribute.AddClassification",
        options=["-classification", "-distribution", "-error"])
    # setting the java object directory avoids issues with correct quoting in option array
    addcls.set_property("classifier", Classifier.make_copy(classifier))
    addcls.inputformat(train)
    addcls.filter(train)  # trains the classifier
    pred = addcls.filter(test)
    if predicted_data is None:
        predicted_data = Instances.template_instances(pred, 0)
    for n in range(pred.num_instances):
        predicted_data.add_instance(pred.get_instance(n))

print("")
print("=== Setup ===")
print("Classifier: " + classifier.to_commandline())
print("Dataset: " + data.relationname)
print("Folds: " + str(folds))
print("Seed: " + str(seed))
print("")
print(evaluation.summary("=== " + str(folds) + " -fold Cross-Validation ==="))
print("")
#print(predicted_data)



# cls.build_classifier(data)

# for index, inst in enumerate(data):
#     pred = cls.classify_instance(inst)
#     dist = cls.distribution_for_instance(inst)
#     print(str(index+1) + ": label index=" + str(pred) + ", class distribution=" + str(dist))

jvm.stop()