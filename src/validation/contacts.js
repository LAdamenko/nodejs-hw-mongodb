import Joi from 'joi';

export const createContactSchema = Joi.object({
    name: Joi.string().min(3).max(20).required().messages({
      'string.base': 'Name should be a string',
      'string.min': 'Name should be at least {#limit} characters',
      'string.max': 'Name should be at most {#limit} characters',
      'any.required': 'Name is required',
    }),
    phoneNumber: Joi.string().min(3).max(20).required(),
    email: Joi.string().email(),
    isFavourite: Joi.boolean(),
    contactType: Joi.string().valid('work', 'home', 'personal').required(),
    userId: Joi.string().required(),
  });

  export const updateContactSchema = Joi.object({
    name: Joi.string().min(3).max(20).messages({
      'string.base': 'Name should be a string',
      'string.min': 'Name should be at least {#limit} characters',
      'string.max': 'Name should be at most {#limit} characters',
    }),
    phoneNumber: Joi.string().min(3).max(20),
    email: Joi.string().email(),
    isFavourite: Joi.boolean(),
    contactType: Joi.string().valid('work', 'home', 'personal'),
  });
