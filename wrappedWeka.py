import os
import traceback

import weka.core.jvm as jvm

from weka.core.converters import Loader

from weka.core.classes import Random
from weka.core.dataset import Instances
from weka.classifiers import Classifier, Evaluation
from weka.filters import Filter

jvm.start()

print()
data_dir = "/home/eric/Raytrace/Arff_Editor_Outputs/"
loader = Loader(classname="weka.core.converters.ArffLoader")
data = loader.load_file('/home/eric/Raytrace/Arff_Editor_Outputs/output_arff_2wkss.arff')#data_dir + "output_arff.arff")
data.class_is_last()
data.delete_attribute(0) #delete source IP attribute
data.delete_attribute(1) #delete destination IP attribute
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

predicted_data = None
evaluation = Evaluation(rand_data)
for i in range(folds):
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