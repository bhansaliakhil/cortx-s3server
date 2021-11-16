package com.seagates3.dao.ldap;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.seagates3.exception.DataAccessException;

public
class FileStore implements AuthStore {

  Map<String, Object> savedDataMap = null;
 private
  final Logger LOGGER = LoggerFactory.getLogger(FileStore.class.getName());

 public
  FileStore(String prefix) {
    try {
      String fileName = "/tmp/" + prefix + ".ser";
      FileInputStream fis = new FileInputStream(fileName);
      ObjectInputStream ois = new ObjectInputStream(fis);
      savedDataMap = (Map)ois.readObject();
      ois.close();
    }
    catch (FileNotFoundException fe) {
      LOGGER.error(
          "FileNotFoundException occurred while reading policy file - " + fe);
      savedDataMap = new HashMap<>();
    }
    catch (IOException | ClassNotFoundException e) {
      LOGGER.error("Exception occurred while reading policy from file - " + e);
    }
  }

  @Override public void save(Map<String, Object> dataMap, Object obj,
                             String prefix) throws DataAccessException {
    savedDataMap.putAll(dataMap);
    try {
      String fileName = "/tmp/" + prefix + ".ser";
      FileOutputStream fos = new FileOutputStream(fileName);
      ObjectOutputStream oos = new ObjectOutputStream(fos);
      oos.writeObject(savedDataMap);
      oos.close();
    }
    catch (IOException e) {
      LOGGER.error("Exception occurred while saving policy into file - " + e);
    }
  }

  @Override public Object find(String key, Object obj,
                               String prefix) throws DataAccessException {
    return savedDataMap.get(key);
  }

  @Override public List findAll(String key, Object obj,
                                String prefix) throws DataAccessException {
    List list = new ArrayList();
    for (Entry<String, Object> entry : savedDataMap.entrySet()) {
      if (entry.getKey().contains(key)) {
        list.add(entry.getValue());
      }
    }
    return list;
  }

  @Override public void delete (String keyToBeRemoved, Object obj,
                                String prefix) throws DataAccessException {
    savedDataMap.remove(keyToBeRemoved);
    try {
      String fileName = "/tmp/" + prefix + ".ser";
      FileOutputStream fos = new FileOutputStream(fileName);
      ObjectOutputStream oos = new ObjectOutputStream(fos);
      oos.writeObject(savedDataMap);
      oos.close();
    }
    catch (IOException e) {
      LOGGER.error("Exception occurred while saving policy into file - " + e);
    }
  }
}