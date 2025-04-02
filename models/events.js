import mongoose from 'mongoose';

const eventSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  date: { type: Date, required: true },
  startTime: { type: String },
  endTime: { type: String },
  venue: { type: String },
  club: { type: String },
  department: { 
    type: String, 
    enum: ['AIML', 'CSE', 'MECH', 'EEE', 'ECE', 'MIN', 'BME', 'OTHER'], 
    default: 'OTHER' 
  },
  status: { 
    type: String, 
    enum: ['NOT YET STARTED', 'ONGOING', 'COMPLETED'], 
    default: 'NOT YET STARTED' 
  },
  posterUrl: { type: String },
  managers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  volunteers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const Event = mongoose.model('Event', eventSchema);

export default Event;
