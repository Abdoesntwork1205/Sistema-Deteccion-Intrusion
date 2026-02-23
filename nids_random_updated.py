import numpy as np
import sys
from sklearn.metrics import accuracy_score, confusion_matrix
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
import sklearn
from sklearn.neighbors import KNeighborsClassifier
import os
from sklearn.preprocessing import LabelEncoder
import tensorflow as tf
from sklearn.preprocessing import Normalizer
import pickle
data_Validate=pd.read_csv('fs_new validation project.csv')
columns = (['protocol_type','service','flag','logged_in','count','srv_serror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_serror_rate','dst_host_rerror_rate','attack'])
data_Validate.columns=columns
protocol_type_le = LabelEncoder()
service_le = LabelEncoder()
flag_le = LabelEncoder()
data_Validate['protocol_type'] = protocol_type_le.fit_transform(data_Validate['protocol_type'])
data_Validate['service'] = service_le.fit_transform(data_Validate['service'])
data_Validate['flag'] = flag_le.fit_transform(data_Validate['flag'])
df_validate=data_Validate.copy(deep=True)
x_validate=df_validate.drop(['attack'],axis=1)
y_validate=pd.DataFrame(df_validate['attack'])
label_encoder = LabelEncoder() 
scaler=MinMaxScaler()
x1=x_validate.copy(deep=True)
scaler=MinMaxScaler()
scaler.fit(x1)
scaled_data=scaler.transform(x1)
scaled_data=pd.DataFrame(scaled_data)
scaled_data.columns= x1.columns
x_validate=scaled_data
knn_bin = pickle.load(open('knn_binary_class.sav', 'rb'))
knn_multi = pickle.load(open('knn_multi_class.sav', 'rb'))
randfor_bin = pickle.load(open('random_forest_binary_class.sav', 'rb'))
randfor_multi = pickle.load(open('random_forest_multi_class.sav', 'rb'))
cnn_bin= tf.keras.models.load_model('latest_cnn_bin.h5')
cnn_multi= tf.keras.models.load_model('latest_cnn_multiclass.h5')
lstm_bin= tf.keras.models.load_model('lstm_latest_bin.h5')
lstm_multi= tf.keras.models.load_model('lstm_latest_multiclass.h5')
def advance():
    #print("KNN ALGORITHM:")
    tp=x_validate.sample()
    val_knn=knn_bin.predict(tp)
    if(val_knn==1):
        for i in val_knn:
            val_knn=i
        print('Algoritmo KNN, Clase Binaria: Ataque')
        tp_knn=knn_multi.predict(tp)
        print('Algoritmo KNN, Tipo Multi-Clase: ',tp_knn)
        if(tp_knn=='dos'):
            print('Descripción KNN: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca una caída del sistema. En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')
        elif(tp_knn=='probe'):
            print('Descripción KNN: El sondeo (Probing) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para obtener acceso ilegal a información personal.')
        elif(tp_knn=='r2l'):
            print('Descripción KNN: El acceso remoto a local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')
        elif(tp_knn=='u2r'):
            print('Descripción KNN: Los ataques de usuario a raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador).')
    elif(val_knn==0):
        print('Algoritmo KNN, Clase Binaria: Normal')
        tp_knn=knn_multi.predict(tp)
        print('Algoritmo KNN, Tipo Multi-Clase: ',tp_knn)
        if(tp_knn=='normal'):
            print('Resumen KNN: Esto es seguro.')

    #print("RANDOM FOREST ALGORITHM:")    
    val_randfor=randfor_bin.predict(tp)
    if(val_randfor==1):
        print('Algoritmo RF, Clase Binaria: Ataque')
        #print('KNN Binary Class Type : ATTACK')
        tp_rnd_for=knn_multi.predict(tp)
        for i in tp_rnd_for:
            tp_rnd_for=i
        print('Algoritmo RF, Tipo Multi-Clase: ',tp_rnd_for)
        if(tp_rnd_for=='dos'):
            print('Descripción RF: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca una caída del sistema. En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')
        elif(tp_rnd_for=='probe'):
            print('Descripción RF: El sondeo (Probing) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para obtener acceso ilegal a información personal.')
        elif(tp_rnd_for=='r2l'):
            print('Descripción RF: El acceso remoto a local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')
        elif(tp_rnd_for=='u2r'):
            print('Descripción RF: Los ataques de usuario a raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador).')

        
    elif(val_randfor==0):
        print('Algoritmo RF, Clase Binaria: Normal')
        tp_randfor=randfor_multi.predict(tp)
        print('Algoritmo RF, Tipo Multi-Clase: ',tp_randfor)
        if(tp_randfor=='normal'):
            print('Resumen RF: Esto es seguro.')
    tp1=tp
    scaler = Normalizer().fit(tp1)
    tp1 = scaler.transform(tp1)
    np.set_printoptions(precision=3)
    tp1 = np.reshape(tp1, (tp1.shape[0],1, tp1.shape[1]))
    val_cnn=cnn_bin.predict(tp1,verbose=False)
    for i in val_cnn:
        for j in i:
            val_cnn=round(j)
    if(val_cnn==1):
        print('Algoritmo CNN, Clase Binaria: Ataque')
        tp1=tp
        scaler = Normalizer().fit(tp1)
        tp1 = scaler.transform(tp1)
        np.set_printoptions(precision=3)
        tp1 = np.reshape(tp1, (tp1.shape[0], tp1.shape[1],1))
        tp_cnn=cnn_multi.predict(tp1,verbose=0)
        l=[]
        for i in tp_cnn:
            for j in i:
                l.append(round(j))
        if(l[0]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: DoS')
            print('Descripción CNN: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca una caída del sistema. En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')
        elif(l[2]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: Probe')
            print('Descripción CNN: El sondeo (Probing) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para obtener acceso ilegal a información personal.')
        elif(l[3]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: R2L')
            print('Descripción CNN: El acceso remoto a local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')
        elif(l[4]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: U2R')
            print('Descripción CNN: Los ataques de usuario a raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador).')
        elif(l[1]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: Normal')
            print('Resumen CNN: Esto es seguro.')
    elif(val_cnn==0):
        print('Algoritmo CNN, Clase Binaria: Normal')
        tp1=tp
        scaler = Normalizer().fit(tp1)
        tp1 = scaler.transform(tp1)
        np.set_printoptions(precision=3)
        tp1 = np.reshape(tp1, (tp1.shape[0], tp1.shape[1],1))
        tp_cnn=cnn_multi.predict(tp1,verbose=0)
        l=[]
        for i in tp_cnn:
            for j in i:
                l.append(round(j))
        if(l[0]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: DoS')
            print('Descripción CNN: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca una caída del sistema. En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')
        elif(l[2]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: Probe')
            print('Descripción CNN: El sondeo (Probing) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para obtener acceso ilegal a información personal.')
        elif(l[3]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: R2L')
            print('Descripción CNN: El acceso remoto a local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')
        elif(l[4]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: U2R')
            print('Descripción CNN: Los ataques de usuario a raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador).')
        elif(l[1]==1):
            print('Algoritmo CNN, Tipo Multi-Clase: Normal')
            print('Resumen CNN: Esto es seguro.')

    #print("LSTM ALGORITHM:")
    tp1=tp
    scaler = Normalizer().fit(tp1)
    tp1 = scaler.transform(tp1)
    np.set_printoptions(precision=3)
    tp1 = np.reshape(tp1, (tp1.shape[0],1, tp1.shape[1]))
    val_lstm=lstm_bin.predict(tp1,verbose=False)
    for i in val_lstm:
        for j in i:
            val_lstm=round(j)
    if(val_lstm==1):
        print('Algoritmo LSTM, Clase Binaria: Ataque')
        tp1=tp
        scaler = Normalizer().fit(tp1)
        tp1 = scaler.transform(tp1)
        np.set_printoptions(precision=3)
        tp1 = np.reshape(tp1, (tp1.shape[0], 1,tp1.shape[1]))
        tp_lstm=lstm_multi.predict(tp1,verbose=0)
        #tp_lstm=lstm_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_lstm:
            for j in i:
                l.append(round(j))
        if(l[0]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: DoS')
            print('Descripción LSTM: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca una caída del sistema. En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')
        elif(l[2]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: Probe')
            print('Descripción LSTM: El sondeo (Probing) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para obtener acceso ilegal a información personal.')
        elif(l[3]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: R2L')
            print('Descripción LSTM: El acceso remoto a local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')
        elif(l[4]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: U2R')
            print('Descripción LSTM: Los ataques de usuario a raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador).')
        elif(l[1]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: Normal')
            print('Resumen LSTM: Esto es seguro.')
    elif(round(val_lstm)==0):
        print('Algoritmo LSTM, Clase Binaria: Normal')
        tp1=tp
        scaler = Normalizer().fit(tp1)
        tp1 = scaler.transform(tp1)
        np.set_printoptions(precision=3)
        tp1 = np.reshape(tp1, (tp1.shape[0], 1,tp1.shape[1]))
        tp_lstm=lstm_multi.predict(tp1,verbose=0)
        #tp_lstm=lstm_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_lstm:
            for j in i:
                l.append(round(j))
        if(l[0]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: DoS')
            print('Descripción LSTM: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca una caída del sistema. En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')
        elif(l[2]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: Probe')
            print('Descripción LSTM: El sondeo (Probing) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para obtener acceso ilegal a información personal.')
        elif(l[3]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: R2L')
            print('Descripción LSTM: El acceso remoto a local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')
        elif(l[4]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: U2R')
            print('Descripción LSTM: Los ataques de usuario a raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador).')
        elif(l[1]==1):
            print('Algoritmo LSTM, Tipo Multi-Clase: Normal')
            print('Resumen LSTM: Esto es seguro.')
advance()
