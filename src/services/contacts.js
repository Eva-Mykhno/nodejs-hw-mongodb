import { contactsCollection } from '../db/models/contacts.js';

export const getAllContacts = async () => {
  const contacts = await contactsCollection.find();
  return contacts;
};

export const getContactByID = async (contactID) => {
  const contact = await contactsCollection.findById(contactID);
  return contact;
};
