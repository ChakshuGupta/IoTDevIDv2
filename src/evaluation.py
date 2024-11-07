import numpy as np
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.metrics import accuracy_score
from sklearn.metrics import balanced_accuracy_score
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix

from sklearn.tree import DecisionTreeClassifier

from collections import Counter
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import sklearn
import time


altime=0

ml_list={"DT" :DecisionTreeClassifier(criterion='entropy', max_depth=28, max_features=16,min_samples_split= 7)}


def target_name(name):
    df = pd.read_csv(name,usecols=["Label"])
    target_names=sorted(list(df["Label"].unique()))
    return target_names


def most_frequent(List):
    occurence_count = Counter(List)
    occurence_count={k: v for k, v in sorted(occurence_count.items(), key=lambda item: item[1],reverse=True)}
    big=list(occurence_count.values())
    big=big.count(big[0])
    return list(occurence_count.keys())[np.random.randint(big)]


def split(a, n):
    k, m = divmod(len(a), n)
    return (a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))


def create_exception(df): 
    exception_list=[]
    dominant_mac=[]
    for i in df['aggregated'].unique():
        k=df[df['aggregated']==i]
        for ii in ['MAC']:
            hist = {}
            for x in k[ii].values:
                hist[x] = hist.get(x, 0) + 1
            hist=dict(sorted(hist.items(), key=lambda item: item[1],reverse=True))
            temp=next(iter(hist))
            if temp not in dominant_mac:
                dominant_mac.append(temp)
            else:
                exception_list.append(temp)
    return exception_list


def merged(m_test, predict, step, mixed):
    second=time.time()
    mac_test=[]
    for q in m_test:
        mac_test.append(q)

    d_list=sorted(list(m_test.unique()))
    devices={}
    for q in d_list:
        devices[q]=[]    

    new_y=[0]*len(m_test)
    for q,qq in enumerate(mac_test):
        devices[qq].append(q)
    for q in devices:
        a = [devices[q][j:j + step] for j in range(0, len(devices[q]), step)]  
        for qq in a:
            step_list=[]
            for qqq in qq:
                step_list.append(predict[qqq])
            add=most_frequent(list(step_list))
            for qqq in qq:
                new_y[qqq]=add
    results=pd.DataFrame(m_test)
    results["aggregated"]=new_y # Only aggregated results
    results["normal"]=predict
    
    #MIXED METHOD
    if mixed:
        exception=create_exception(results)
        for q in exception:
            results.loc[results.MAC == q, 'aggregated'] = results['normal']

    return results["aggregated"].values,time.time()-second


def score(altime,train_time,test_time,predict,y_test,class_based_results,dname,ii, target_names):
    precision=[]
    recall=[]
    f1=[]
    accuracy=[]
    total_time=[]
    kappa=[]
    accuracy_b=[]
    
    rc=sklearn.metrics.recall_score(y_test, predict,average= "macro")
    pr=sklearn.metrics.precision_score(y_test, predict,average= "macro")
    f_1=sklearn.metrics.f1_score(y_test, predict,average= "macro")        
    report = classification_report(y_test, predict, target_names=target_names,output_dict=True)
    cr = pd.DataFrame(report).transpose()
    if class_based_results.empty:
        class_based_results =cr
    else:
        class_based_results = class_based_results.add(cr, fill_value=0)
    precision.append(float(pr))
    recall.append(float(rc))
    f1.append(float(f_1))
    accuracy_b.append(balanced_accuracy_score( y_test,predict))
    accuracy.append(accuracy_score(y_test, predict))

    kappa.append(round(float(sklearn.metrics.cohen_kappa_score(y_test, predict, 
    labels=None, weights=None, sample_weight=None)),15))
    print ('%-15s %-6s  %-5s %-5s %-5s %-5s %-8s %-5s %-8s %-8s%-8s%-8s' % (dname,ii[0:6],str(round(np.mean(accuracy),2)),str(round(np.mean(accuracy_b),2)),
        str(round(np.mean(precision),2)), str(round(np.mean(recall),2)),str(round(np.mean(f1),4)), 
        str(round(np.mean(kappa),2)),str(round(np.mean(train_time),2)),str(round(np.mean(test_time),2)),str(round(np.mean(test_time)+np.mean(train_time),2)),str(round(np.mean(altime),2))))
    lines=(str(dname)+","+str(ii)+","+str(round(np.mean(accuracy),15))+","+str(round(np.mean(accuracy_b),15))+","+str(round(np.mean(precision),15))+","+ str(round(np.mean(recall),15))+","+str(round(np.mean(f1),15))+","+str(round(np.mean(kappa),15))+","+str(round(np.mean(train_time),15))+","+str(round(np.mean(test_time),15))+","+str(altime)+"\n")
    return lines,class_based_results



def compute_result(y_test, predict, target_names, output_csv, m_test, step, mixed, dname, train_time, test_time, ml_algo):

    ths = open(output_csv, "w")
    ths.write("Dataset,T,CV,ML algorithm,Acc,b_Acc,Precision, Recall , F1-score, kappa ,tra-Time,test-Time,Al-Time\n")
    num_reps = 10

    class_based_results=pd.DataFrame()#"" #pd.DataFrame(0, index=np.arange((len(target_names)+3)), columns=["f1-score","precision","recall","support"])
    cm = pd.DataFrame()

    for i in range(num_reps):

        if step==1:
            altime=0
            lines,class_based_results = score(altime, train_time, test_time, predict[i], y_test[i], class_based_results, dname, ml_algo, target_names)
        else:
            predict[i],altime = merged(m_test,predict[i],step,mixed)
            lines,class_based_results = score(altime, train_time, test_time, predict[i], y_test[i], class_based_results, dname, ml_algo, target_names)

        ths.write(lines)

        df_cm = pd.DataFrame(confusion_matrix(y_test[i], predict[i]))
        if cm.empty:
            cm =df_cm
        else:
            cm = cm.add(df_cm, fill_value=0)
    
    class_based_results=class_based_results/num_reps
    print(class_based_results)
    class_based_results.to_csv(dname + "-class_based_results.csv")

    if True :
        cm = cm//num_reps
        graph_name = output_csv + ml_algo + "_confusion matrix.pdf"   
        plt.figure(figsize = (40,28))
        sns.heatmap(cm, xticklabels=target_names, yticklabels=target_names, annot=True, fmt='g')
        plt.savefig(graph_name, bbox_inches='tight')
        plt.show()
        print("\n\n\n")             

    ths.close()


def train_model(x_train, y_train, ml_algo):

    models = []

    
    print ('%-15s %-3s %-3s %-6s  %-5s %-5s %-5s %-5s %-8s %-5s %-8s %-8s%-8s%-8s'%
            ("Dataset","T","CV","ML alg","Acc","b_Acc","Prec", "Rec" , "F1", "kap" ,"tra-T","test-T","total","al-time"))
    
    if ml_algo in ["GB","SVM"]: #for slow algorithms.
        repetition=10 
    else:
        repetition=10

    for i in range(repetition):
        #TRAIN
        clf = ml_list[ml_algo]#choose algorithm from ml_list dictionary
        
        second = time.time()
        
        clf.fit(x_train, y_train)
        train_time = (float((time.time()-second)) )
        
        second = time.time()
        
        models.append(clf)

    return train_time, models


def test_model(x_test, y_test, models):

    y_true_per_rep = []
    y_predict_per_rep = []

    repetition=10
    
    for i in range(repetition):
        #TEST
        results_y=[]
        results_y.append(y_test)     
        
        second=time.time()
        predict = models[i].predict(x_test)
        test_time=(float((time.time()-second)) )
        
        y_true_per_rep.append(y_test)
        y_predict_per_rep.append(predict)

    
    return y_true_per_rep, y_predict_per_rep, test_time