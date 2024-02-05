import MySQLdb, logging

class my_sql(object):
  def get_link(self,my_host,my_user,my_pass,my_db):
    self.con=MySQLdb.connect(my_host,my_user,my_pass,my_db)
    logging.debug(self.con)
    if(self.con==None):
      if(debug==1): logging.debug("Can't connect to database")
    else:
      logging.debug('connected to database')

  def run_query(self,prepared_sql,data_tpl):
    cur=self.con.cursor()
    cur.execute(prepared_sql,data_tpl)
    self.con.commit()
    msg="rows affected: {}".format(cur.rowcount)
    logging.debug(msg)
    return cur

  def get_single_row(self,cur):
    return cur.fetchone()

  def close_cursor(self,cur):
    cur.close()

  def close_link(self):
    self.con.close()

  def get_column_names(self,cur):
    fields=()
    for field in cur.description:
      fields=fields+(field[0],)
    return fields
