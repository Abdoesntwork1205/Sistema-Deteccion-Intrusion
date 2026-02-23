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
import pickle
from sklearn import preprocessing
from sklearn.preprocessing import Normalizer
prot_type=sys.argv[1]
service=sys.argv[2]
flag=sys.argv[3]
log_in=int(sys.argv[4])
count=int(sys.argv[5])
srv_serr_rate=float(sys.argv[6])
srv_rerr_rate=float(sys.argv[7])
sm_srv_rate=float(sys.argv[8])
diff_srv_rate=float(sys.argv[9])
dst_hst_count=int(sys.argv[10])
dst_hst_ser_count=int(sys.argv[11])
dst_hst_same_srv_count=float(sys.argv[12])
dst_hst_diff_srv_rate=float(sys.argv[13])
dst_hst_same_src_port_rate=float(sys.argv[14])
dst_hst_serr_rate=float(sys.argv[15])
dst_hst_rerr_rate=float(sys.argv[16])

prot_type_map={'tcp':1,'udp':2,'icmp':0}
serv_type_map={'IRC': 0,
 'X11': 1,
 'Z39_50': 2,
 'http_8001': 3,
 'auth': 4,
 'bgp': 5,
 'courier': 6,
 'csnet_ns': 7,
 'ctf': 8,
 'daytime': 9,
 'discard': 10,
 'domain': 11,
 'domain_u': 12,
 'echo': 13,
 'eco_i': 14,
 'ecr_i': 15,
 'efs': 16,
 'exec': 17,
 'finger': 18,
 'ftp': 19,
 'ftp_data': 20,
 'gopher': 21,
 'harvest': 22,
 'hostnames': 23,
 'http': 24,
 'http_2784': 25,
 'http_443': 26,
 'aol': 27,
 'imap4': 28,
 'iso_tsap': 29,
 'klogin': 30,
 'kshell': 31,
 'ldap': 32,
 'link': 33,
 'login': 34,
 'mtp': 35,
 'name': 36,
 'netbios_dgm': 37,
 'netbios_ns': 38,
 'netbios_ssn': 39,
 'netstat': 40,
 'nnsp': 41,
 'nntp': 42,
 'ntp_u': 43,
 'other': 44,
 'pm_dump': 45,
 'pop_2': 46,
 'pop_3': 47,
 'printer': 48,
 'private': 49,
 'red_i': 50,
 'remote_job': 51,
 'rje': 52,
 'shell': 53,
 'smtp': 54,
 'sql_net': 55,
 'ssh': 56,
 'sunrpc': 57,
 'supdup': 58,
 'systat': 59,
 'telnet': 60,
 'tftp_u': 61,
 'tim_i': 62,
 'time': 63,
 'urh_i': 64,
 'urp_i': 65,
 'uucp': 66,
 'uucp_path': 67,
 'vmnet': 68,
 'whois': 69}
flag_type_map={'OTH': 0,
 'REJ': 1,
 'RSTO': 2,
 'RSTOS0': 3,
 'RSTR': 4,
 'S0': 5,
 'S1': 6,
 'S2': 7,
 'S3': 8,
 'SF': 9,
 'SH': 10}
prot_type=prot_type_map.get(prot_type)
service=serv_type_map.get(service)
flag=flag_type_map.get(flag)
l=[]
l.append(prot_type)
l.append(service)
l.append(flag)
l.append(log_in)
l.append(count)
l.append(srv_serr_rate)
l.append(srv_rerr_rate)
l.append(sm_srv_rate)
l.append(diff_srv_rate)
l.append(dst_hst_count)
l.append(dst_hst_ser_count)
l.append(dst_hst_same_srv_count)
l.append(dst_hst_diff_srv_rate)
l.append(dst_hst_same_src_port_rate)
l.append(dst_hst_serr_rate)
l.append(dst_hst_rerr_rate)
l1 = preprocessing.normalize([l])
knn_bin = pickle.load(open('knn_binary_class.sav', 'rb'))
knn_multi = pickle.load(open('knn_multi_class.sav', 'rb'))
randfor_bin = pickle.load(open('random_forest_binary_class.sav', 'rb'))
randfor_multi = pickle.load(open('random_forest_multi_class.sav', 'rb'))
cnn_bin= tf.keras.models.load_model('latest_cnn_bin.h5')
cnn_multi= tf.keras.models.load_model('latest_cnn_multiclass.h5')
lstm_bin= tf.keras.models.load_model('lstm_latest_bin.h5')
lstm_multi= tf.keras.models.load_model('lstm_latest_multiclass.h5')
val_knn=knn_bin.predict(l1)
if(val_knn[0]==0):
    print('Algoritmo KNN, Clase Binaria: Normal')
else:
    print('Algoritmo KNN, Clase Binaria: Ataque')
#print('KNN Algorithm multi class:',knn_multi.predict(l1))
tp_knn=knn_multi.predict(l1)
for i in tp_knn:
    tp_knn=i

print('Algoritmo KNN, Tipo Multi-Clase: ',tp_knn)
if(tp_knn=='dos'):
   print('Descripción KNN: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca un fallo del sistema (crash). En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')
elif(tp_knn=='probe'):
   print('Descripción KNN: El "Probing" (Sondeo) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para el acceso ilegal a información personal.')
elif(tp_knn=='r2l'):
   print('Descripción KNN: El acceso de Remoto a Local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')
elif(tp_knn=='u2r'):
   print('Descripción KNN: Los ataques de Usuario a Raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador o root).')
else:
    print('Resumen KNN: Los datos son seguros.')
val_rnd=randfor_bin.predict(l1)
if(val_rnd[0]==0):
    print('Algoritmo Random Forest, Clase Binaria: Normal')
else:
    print('Algoritmo Random Forest, Clase Binaria: Ataque')
    
#print('Random Forsest Algorithm Multi class:',randfor_multi.predict(l1))
tp_randfor=randfor_multi.predict(l1)
for i in tp_randfor:
    tp_randfor=i
print('Algoritmo Random Forest, Tipo Multi-Clase: ',tp_randfor)
if(tp_randfor=='dos'):
   print('Descripción RF: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca un fallo del sistema (crash). En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')
elif(tp_randfor=='probe'):
   print('El "Probing" (Sondeo) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para el acceso ilegal a información personal.')
elif(tp_randfor=='r2l'):
   print('Descripción RF: El acceso de Remoto a Local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')
elif(tp_randfor=='u2r'):
   print('Descripción RF: Los ataques de Usuario a Raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador o root).')
else:
    print('Resumen RF: Los datos son seguros.')
tp1=l1
scaler = Normalizer().fit(tp1)
tp1 = scaler.transform(tp1)
np.set_printoptions(precision=3)
tp1 = np.reshape(tp1, (tp1.shape[0],1, tp1.shape[1]))
val_cnn=cnn_bin.predict(tp1,verbose=0)
tp=[]
for i in val_cnn:
    for j in i:
        tp.append(round(j))
if(tp[0]==1):
    print('Algoritmo CNN, Clase Binaria: Ataque')
else:
    print('Algoritmo CNN, Clase Binaria: Normal')
tp1=l1
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
   print('Descripción CNN: El sondeo (Probing) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para obtener acceso ilegal a información personal')

elif(l[3]==1):
   print('Algoritmo CNN, Tipo Multi-Clase: R2L')
   print('Descripción CNN: El acceso remoto a local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')

elif(l[4]==1):
   print('Algoritmo CNN, Tipo Multi-Clase: U2R')
   print('Descripción CNN: Los ataques de usuario a raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador).')

elif(l[1]==1):
   print('Algoritmo CNN, Tipo Multi-Clase: Normal')
   print('Resumen CNN: Los datos son seguros.')

tp1=l1
scaler = Normalizer().fit(tp1)
tp1 = scaler.transform(tp1)
np.set_printoptions(precision=3)
tp1 = np.reshape(tp1, (tp1.shape[0],1, tp1.shape[1]))
val_lstm=lstm_bin.predict(tp1,verbose=0)
tp=[]
for i in val_lstm:
  for j in i:
      tp.append(round(j))
if(tp[0]==1):
    print('Algoritmo LSTM, Clase Binaria: Ataque')
else:
    print('Algoritmo LSTM, Clase Binaria: Normal')
tp1=l1
scaler = Normalizer().fit(tp1)
tp1 = scaler.transform(tp1)
np.set_printoptions(precision=3)
tp1 = np.reshape(tp1, (tp1.shape[0],1, tp1.shape[1]))
tp_lstm=lstm_multi.predict(tp1,verbose=0)
l=[]
for i in tp_lstm:
    for j in i:
        l.append(round(j))
if(l[0]==1):
   print('Algoitmo LSTM, Tipo Multi-Clase: DoS')
   print('Descripción LSTM: Un ataque de Denegación de Servicio (DoS) es un ataque destinado a inhabilitar una máquina o red, haciéndola inaccesible para sus usuarios previstos. Los ataques DoS logran esto inundando el objetivo con tráfico o enviándole información que provoca una caída del sistema. En ambos casos, el ataque DoS priva a los usuarios legítimos (es decir, empleados, miembros o titulares de cuentas) del servicio o recurso que esperaban.')

elif(l[2]==1):
   print('Algoitmo LSTM, Tipo Multi-Clase: Probe')
   print('Descripción LSTM: El sondeo (Probing) es otro tipo de ataque en el que el intruso escanea los dispositivos de red para determinar debilidades en el diseño de la topología o algunos puertos abiertos, para luego utilizarlos en el futuro para obtener acceso ilegal a información personal.')

elif(l[3]==1):
   print('Algoitmo LSTM, Tipo Multi-Clase: R2L')
   print('Descripción LSTM: El acceso remoto a local (R2L) es un tipo de ataque a redes informáticas en el que un intruso envía un conjunto de paquetes a otra computadora o servidor a través de una red en la que no tiene permiso de acceso como usuario local.')

elif(l[4]==1):
   print('Algoitmo LSTM, Tipo Multi-Clase: U2R')
   print('Descripción LSTM: Los ataques de usuario a raíz (U2R) son otro tipo de ataque en el que el intruso intenta acceder a los recursos de la red como un usuario normal y, tras varios intentos, el intruso se convierte en un usuario con acceso total (administrador).')

elif(l[1]==1):
   print('Algoitmo LSTM, Tipo Multi-Clase: Normal')
   print('Resumen LSTM: Los datos son seguros.')

