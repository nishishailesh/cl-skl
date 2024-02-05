import sys, logging, os, datetime
import config, time
logging.basicConfig(filename=config.log_filename,level=logging.DEBUG,force=True)  

import common_modules.common_mysql as myassql
import importlib,bcrypt
import urllib.parse #simple urllib do not work. it consume a lot of memory. so, setup to import perticular module
import secrets
import config

import string
import random
import numpy
import matplotlib.pyplot as plt 
mlog=logging.getLogger('matplotlib')
import pprint

import io
import base64

sys.path.append(config.mysql_secret_file_location)
astm_var = importlib.import_module(config.mysql_secret_module, package=None)

header1='''<link  rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css" 
                  integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" 
                  crossorigin="anonymous">'''

def do_work(environ):
    #post is from file like object. and no seek to 0. os read once and make available where ever required
    post=get_post(environ)
    if(b'action' not in post):
      ret=[login()]
    else:
      public_key=verify_user(post)
      if(public_key!=False):
        if(post[b'action']==b'login'):
          ret=[
                open_new_window(post[b'username'],public_key),
                display_menu(post[b'username'],public_key)
              ]
        elif(post[b'action']==b'open_new_window'):
          ret=[
                open_new_window(post[b'username'],public_key),
                display_menu(post[b'username'],public_key)
              ]
        elif(post[b'action']==b'analyse_qc'):
          ret=[
                open_new_window(post[b'username'],public_key),
                display_menu(post[b'username'],public_key),
                get_qc_data(post[b'username'],public_key)
              ]
        elif(post[b'action']==b'show_qc_analysis'):
          ret=[
                b'<html><head>'+header1.encode("UTF-8")+b'</head><body>',
                open_new_window(post[b'username'],public_key),
                display_menu(post[b'username'],public_key),
                echo_post(post),
                b'<h3 class="bg-success">QC Analysis</h3>',
                display_qc_data_from_database(post)
              ]
      else:
        ret=[
              b'login is not successful or no communication with server for long',
              login()
              #echo_post(post)
            ]
    return ret
    
##########################Work function#########################

def login():
  form='''
  <form method=post>
  <input class=text-danger type=text name=username>
  <input type=password name=password>
  <input type=submit name=action value=login>
  <form>
  </body>
  </html>'''
  return form.encode("UTF-8")

def echo_post(post):
    return '<pre>{}</pre>'.format(post).encode("UTF-8")

def open_new_window(username,public_key):
  form='''
  <form method=post target=_blank>
    <button type=submit name=action value=open_new_window>+</button>
    <input type=hidden name=public_key value=\''''+public_key.decode("UTF-8")+'''\'>
    <input type=hidden name=username value=\''''+username.decode("UTF-8")+ '''\'>
  </form>
  '''
  return form.encode("UTF-8")
  
def display_menu(username,public_key):
  form='''
  <form method=post>
    <button type=submit name=action value=analyse_qc>Analyse QC</button>   
    <input type=hidden name=public_key value=\''''+public_key.decode("UTF-8")+'''\'>
    <input type=hidden name=username value=\''''+username.decode("UTF-8")+ '''\'>
  </form>
  '''
  return form.encode("UTF-8")


def get_qc_data(username,public_key):
  form=header1+'''
  <form method=post>
    <input type=text name=qc_lot placeholder=qc_lot>
    <input type=text name=examination_id placeholder=examination_id>
    <input type=text name=equipment placeholder=equipment>
    <button type=submit name=action value=show_qc_analysis>Show QC Analysis</button>
    <input type=hidden name=public_key value=\''''+public_key.decode("UTF-8")+'''\'>
    <input type=hidden name=username value=\''''+username.decode("UTF-8")+ '''\'>
  </form>
  '''
  return form.encode("UTF-8")  
#########################Support function#########################    
def get_post(environ):
  #environ['wsgi.input'] is file like object
  post={}
  try:
    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    request_body = environ['wsgi.input'].read(request_body_size)
    logging.debug('===POST====')
    logging.debug('request_body={}'.format(request_body))
    if(len(request_body)>0):
      for attr_value_pair in request_body.decode().split("&"):
        pair=attr_value_pair.split("=")
        logging.debug('attr_value_pair={}'.format(pair))
        post[urllib.parse.unquote(pair[0]).encode("UTF-8")]=urllib.parse.unquote(pair[1]).encode("UTF-8")
    logging.debug('===END POST====')
  except (ValueError):
    request_body_size = 0
  logging.debug('UNQUOTED post:{}'.format(post))
  return post
    
  '''
  if password matchs
    save private
    update public for all forms
  else
    if private=public and expiry>current time
      return true
    else
      return false
  '''
  
def verify_user(post):
  if(b'username' in post and b'password' in post):
    logging.debug('username and password are provided')
    #post is dictionary with  strings, not bytes (because split is there for str)
    m=myassql.my_sql()
    m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
    cur=m.run_query('select * from user where user=%s',(post[b'username'].decode("UTF-8"),))
    user_info=m.get_single_row(cur)
    m.close_cursor(cur)
    m.close_link()
    
    logging.debug('user data:{}'.format(user_info))
    logging.debug('post data:{}'.format(post))

    '''
    Python: bcrypt.hashpw(b'mypassword',bcrypt.gensalt(rounds= 4,prefix = b'2b')
    PHP:    password_hash('mypassword',PASSWORD_BCRYPT);

    Python:bcrypt.checkpw(b'text',b'bcrypted password')
    PHP: password_verify('text,'bcrypted password')
    '''
    #try is required to cache NoneType exception when supplied hash is not bcrypt
    try:
      if(bcrypt.checkpw(post[b'password'],user_info[2].encode())):
        #pr,pb=get_private_public()
        public_key=insert_update_private_key(post[b'username'])
        return public_key
      else:
        return False
    except Exception as ex:
      logging.debug('{}'.format(ex))
      return False
  elif(b'public_key' in post):
    return verify_public_key(post[b'username'],post[b'public_key'])
  else:
    return False
  
def verify_public_key(username,public_key):
  current_date_time=datetime.datetime.now()
  private_key_data=retrive_private_key(username)
  logging.debug('public={}:  private={}  : private_key_expiry={}'.format(public_key,private_key_data[0],private_key_data[1],))
  if bcrypt.checkpw(private_key_data[0],public_key)==True and private_key_data[1] > current_date_time:
    dt=datetime.datetime.now()+ datetime.timedelta(minutes=config.key_expiry_period)
    dt_str=dt.strftime("%Y-%m-%dT%H:%M:%S")
    m=myassql.my_sql()
    m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
    cur=m.run_query('update logged set expire=%s where user=%s',
                    (dt_str,username.decode("UTF-8")))
    m.close_cursor(cur)
    m.close_link()   
    return public_key
  else:
    return False

def get_private_public():
  size=50
  chars=string.ascii_uppercase + string.digits
  private=''.join(random.choice(chars) for _ in range(size)).encode()
  public=bcrypt.hashpw(private,bcrypt.gensalt(rounds= 4,prefix = b'2b'))
  logging.debug('Private:{} Public:{}'.format(private,public))
  return (private, public)
  
def insert_update_private_key(username):
  pair=get_private_public()
  dt=datetime.datetime.now()+ datetime.timedelta(minutes=config.key_expiry_period)
  dt_str=dt.strftime("%Y-%m-%dT%H:%M:%S")
  m=myassql.my_sql()
  m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
  cur=m.run_query('insert into logged (user,private,expire) values(%s,%s,%s) on duplicate key update private=%s , expire=%s',
                    (username.decode("UTF-8"),pair[0].decode("UTF-8"),dt_str,pair[0].decode("UTF-8"),dt_str))
  m.close_cursor(cur)
  m.close_link()
  return pair[1]

def retrive_private_key(username):
  m=myassql.my_sql()
  m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
  cur=m.run_query('select * from logged where user=%s',username.decode("UTF-8"))
  logged_info=m.get_single_row(cur)
  m.close_cursor(cur)
  m.close_link()
  logging.debug('logged info:{}'.format(logged_info))  
  return (logged_info[1].encode("UTF-8"),logged_info[2])


#############################QC Functions##########################
def display_qc_data_from_database(post):
  all_values, all_values_without_outliers = retrive_qc_data(post)
  
  all_stat=calculate_qc_statistics(post,all_values)
  img=get_histogram_image_tag(all_stat["histogram"])
  
  all_stat_without_outliers=calculate_qc_statistics(post,all_values_without_outliers)
  wimg=get_histogram_image_tag(all_stat_without_outliers["histogram"])
 
  ret='''
  =========All values statistics==========<br>
  {}<br>
  {}<br>
  {}<br>
  =========Statistics for values which are not outliers==========<br>
  {}<br>
  {}<br>
  {}<br>
  '''.format( all_values,
              display_dictionary(all_stat),
              img,
              
              all_values_without_outliers,
              display_dictionary(all_stat_without_outliers),
              wimg
            )
  return ret.encode("UTF-8")


def retrive_qc_data(post):
  all_values=numpy.array([])
  all_values_without_outliers=numpy.array([])
  m=myassql.my_sql()
  m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
  cur_lot=m.run_query('select * from result where examination_id=%s and result=%s order by sample_id desc limit 1000',(3001,post[b'qc_lot'].decode("UTF-8")))
  data_lot=m.get_single_row(cur_lot)
  while(data_lot!=None):
    cur_equipment=m.run_query('select * from result where examination_id=%s and result=%s and sample_id=%s',(9000,post[b'equipment'].decode("UTF-8"), data_lot[0]))
    data_equipment=m.get_single_row(cur_equipment)
    m.close_cursor(cur_equipment)
    if(data_equipment!=None):
      cur_examination=m.run_query('select * from primary_result where examination_id=%s and sample_id=%s',(post[b'examination_id'].decode("UTF-8"), data_equipment[0]))
      data_examination=m.get_single_row(cur_examination)
      while(data_examination!=None):
        try:
          fl=float(data_examination[2])
          all_values=numpy.append(all_values,fl)
          if(data_examination[3]!=None):
            if(data_examination[3].upper().find("OUTLIER")==-1):
              logging.debug('Not outlier:'+data_examination[2]+':'+data_examination[3].upper())
              all_values_without_outliers=numpy.append(all_values_without_outliers,fl)
            else:
              logging.debug('Outlier:'+data_examination[2]+':'+data_examination[3].upper())
          else:
            all_values_without_outliers=numpy.append(all_values_without_outliers,fl)
        except ValueError:
          logging.debug(data_examination[2]+ 'is not float')
        data_examination=m.get_single_row(cur_examination)
      m.close_cursor(cur_examination)
    data_lot=m.get_single_row(cur_lot)  
  m.close_cursor(cur_lot)
  m.close_link()
  logging.debug('{}'.format(all_values))
  return (all_values,all_values_without_outliers)

def calculate_qc_statistics(all_values):
  mean=numpy.average(all_values)
  median=numpy.median(all_values)
  sd=numpy.std(all_values)    
  cv=(sd/mean)*100
  hg_min=numpy.min(all_values)
  hg_max=numpy.max(all_values)  
  logging.debug(numpy.linspace(hg_max,hg_min,10))
  hg=numpy.histogram(all_values,numpy.linspace(hg_min,hg_max,40))
  logging.debug('histogram{}'.format(hg))
  return {"mean":mean,"median":median,"sd":sd,"cv":cv,"minimum":hg_min,"maximum":hg_max,"histogram":hg}
  
def get_histogram_image_tag(hg):
  plt.stairs(hg[0],hg[1], fill=True)
  f = io.BytesIO()
  plt.savefig(f, format='png')
  f.seek(0)
  data=f.read()
  f.close()
  plt.close() 
  data_uri = base64.b64encode(data).decode("UTF-8")
  #logging.debug(data_uri)
  img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)
  return img_tag
  
def display_qc_data_from_database_backup(post):
  all_values=numpy.array([])
  all_values_without_outliers=numpy.array([])
  m=myassql.my_sql()
  m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
  cur_lot=m.run_query('select * from result where examination_id=%s and result=%s order by sample_id desc limit 1000',(3001,post[b'qc_lot'].decode("UTF-8")))
  data_lot=m.get_single_row(cur_lot)
  ret='<table class="table table-sm table-striped">'
  while(data_lot!=None):
    cur_equipment=m.run_query('select * from result where examination_id=%s and result=%s and sample_id=%s',(9000,post[b'equipment'].decode("UTF-8"), data_lot[0]))
    data_equipment=m.get_single_row(cur_equipment)
    m.close_cursor(cur_equipment)
    if(data_equipment!=None):
      cur_examination=m.run_query('select * from primary_result where examination_id=%s and sample_id=%s',(post[b'examination_id'].decode("UTF-8"), data_equipment[0]))
      data_examination=m.get_single_row(cur_examination)
      while(data_examination!=None):
        ret=ret+'<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(post[b'qc_lot'].decode("UTF-8"),post[b'equipment'].decode("UTF-8"),data_examination[0],data_examination[1],data_examination[2],data_examination[3],data_examination[4])
        try:
          fl=float(data_examination[2])
          all_values=numpy.append(all_values,fl)
          if(data_examination[3]!=None):
            if(data_examination[3].upper().find("OUTLIER")==-1):
              logging.debug('Not outlier:'+data_examination[2]+':'+data_examination[3].upper())
              all_values_without_outliers=numpy.append(all_values_without_outliers,fl)
            else:
              logging.debug('Outlier:'+data_examination[2]+':'+data_examination[3].upper())
          else:
            all_values_without_outliers=numpy.append(all_values_without_outliers,fl)
        except ValueError:
          logging.debug(data_examination[2]+ 'is not float')
        data_examination=m.get_single_row(cur_examination)
      m.close_cursor(cur_examination)
    data_lot=m.get_single_row(cur_lot)
    
  ret=ret+'</table>' 
  m.close_cursor(cur_lot)
  m.close_link()
  logging.debug('{}'.format(all_values))
  
  mean=numpy.average(all_values)
  median=numpy.median(all_values)
  sd=numpy.std(all_values)    
  cv=(sd/mean)*100
  
  wmean=numpy.average(all_values_without_outliers)
  wmedian=numpy.median(all_values_without_outliers)
  wsd=numpy.std(all_values_without_outliers)    
  wcv=(wsd/wmean)*100

  hg_min=numpy.min(all_values)
  hg_max=numpy.max(all_values)
  
  #hg=numpy.histogram(all_values,hg_min,hg_max,(hg_max-hg_min)/10)
  logging.debug(numpy.linspace(hg_max,hg_min,10))
  hg=numpy.histogram(all_values,numpy.linspace(hg_min,hg_max,40))
  logging.debug('histogram{}'.format(hg))
  plt.stairs(hg[0],hg[1], fill=True)
  f = io.BytesIO()
  plt.savefig(f, format='png')
  f.seek(0)
  data=f.read()
  f.close()
  plt.close() 

  data_uri = base64.b64encode(data).decode("UTF-8")
  #logging.debug(data_uri)
  img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)


  whg_min=numpy.min(all_values_without_outliers)
  whg_max=numpy.max(all_values_without_outliers)
  #whg=numpy.histogram(all_values,whg_min,whg_max,(whg_max-whg_min)/10)
  
  whg=numpy.histogram(all_values,numpy.linspace(whg_min,whg_max,40))
  #whg=numpy.histogram(all_values_without_outliers,numpy.arange(numpy.min(all_values_without_outliers),numpy.max(all_values_without_outliers),2))
  logging.debug('histogram{}'.format(whg))
  plt.stairs(whg[0],whg[1], fill=True)
  wf = io.BytesIO()
  plt.savefig(wf, format='png')
  wf.seek(0)
  wdata=wf.read()
  wf.close()
  plt.close() 

  wdata_uri = base64.b64encode(wdata).decode("UTF-8")
  #logging.debug(wdata_uri)
  wimg_tag = '<img src="data:image/png;base64,{0}">'.format(wdata_uri)
  
  
  ret=ret+'''
  =========All values statistics==========<br>
  all_values:{}<br>
  median={}<br>
  mean={}<br>
  sd={}<br>
  cv%={}
  
  <br>=========Statistics for values which are not outliers==========<br>
  all_values_without_outliers:{}<br>
  wmedian={}<br>
  wmean={}<br>
  wsd={}<br>
  wcv%={}<br>

  {}<br>
  {}
  
  '''.format(all_values,median,mean,sd,cv,all_values_without_outliers,wmedian,wmean,wsd,wcv,img_tag,wimg_tag)
  return ret.encode("UTF-8")

  

def display_dictionary(dictionary):
  ret='<table class="table table-sm table-striped">'
  for data_key in dictionary:
    ret=ret+'<tr><td>{}</td><td>{}</td></tr>'.format(data_key,dictionary[data_key])
  ret=ret+'</table>'
  return ret
