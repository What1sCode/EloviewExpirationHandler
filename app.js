console.log('🚀 Starting Zendesk EV Expiration Handler...');
console.log('Node version:', process.version);
console.log('Environment:', process.env.NODE_ENV);
console.log('Port:', process.env.PORT);

const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const crypto = require('crypto');
const app = express();

console.log('✅ All modules loaded successfully');

// Configuration - USE ENVIRONMENT VARIABLES
const ZENDESK_DOMAIN = process.env.ZENDESK_DOMAIN || 'https://elotouchcare.zendesk.com';
const API_TOKEN = process.env.ZENDESK_API_TOKEN;
const ZENDESK_EMAIL = process.env.ZENDESK_EMAIL;
const WEBHOOK_SECRET = process.env.ZENDESKEVM_WEBHOOK_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const TARGET_TAG = 'ev_message_expire';
const PROCESSED_TAG = 'ev_expire_processed';
const TARGET_SUBJECT = 'Customer subscription expired';
const MACRO_ID = process.env.MACRO_ID || '35840245831575'; // Expiration MACRO - NOT THE WELCOME MACRO!
const TARGET_GROUP_ID = process.env.TARGET_GROUP_ID || '31112854673047'; // TS - NA/LATAM group ID

// Validate required environment variables on startup
const requiredEnvVars = {
  ZENDESK_API_TOKEN: API_TOKEN,
  ZENDESK_EMAIL: ZENDESK_EMAIL,
  ZENDESKEVM_WEBHOOK_SECRET: WEBHOOK_SECRET,
  ADMIN_SECRET: ADMIN_SECRET
};
const missingVars = Object.entries(requiredEnvVars).filter(([, v]) => !v).map(([k]) => k);
if (missingVars.length > 0) {
  console.error('❌ FATAL: Missing required environment variables!');
  missingVars.forEach(v => console.error(`   - ${v}: [MISSING]`));
  process.exit(1);
}

// In-memory cache to prevent duplicate processing within short time windows
const recentlyProcessed = new Map();
const PROCESSING_COOLDOWN_MS = 60000; // 1 minute cooldown

// Clean up old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ticketId, timestamp] of recentlyProcessed.entries()) {
    if (now - timestamp > PROCESSING_COOLDOWN_MS) {
      recentlyProcessed.delete(ticketId);
    }
  }
}, 300000);

// Webhook signature verification middleware
function verifyZendeskSignature(req, res, next) {
  const signature = req.headers['x-zendesk-webhook-signature'];
  const timestamp = req.headers['x-zendesk-webhook-signature-timestamp'];

  if (!signature || !timestamp) {
    console.warn('Webhook rejected: missing signature headers');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const payload = timestamp + JSON.stringify(req.body);
  const expected = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(payload)
    .digest('base64');

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    console.warn('Webhook rejected: invalid signature');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}

// Admin endpoint auth middleware
function verifyAdminSecret(req, res, next) {
  const provided = req.headers['x-admin-secret'];
  if (!provided || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(ADMIN_SECRET))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Middleware
app.use(express.json());

// Helper function to create authenticated Zendesk API headers
function getZendeskHeaders() {
  // Try different authentication methods
  const authString = Buffer.from(`${ZENDESK_EMAIL}/token:${API_TOKEN}`).toString('base64');
  
  return {
    'Content-Type': 'application/json',
    'Authorization': `Basic ${authString}`
    // Alternative: 'X-API-Key': API_TOKEN
  };
}

// Extract contact information from ticket content
function extractContactInfo(ticketContent) {
  const $ = cheerio.load(ticketContent);
  const contactInfo = {
    firstName: '',
    lastName: '',
    email: '',
    phone: ''
  };

  try {
    console.log('Raw ticket content preview:', ticketContent.substring(0, 500));

    // Method 1: Look for table rows with contact information
    $('table tr').each((index, element) => {
      const cells = $(element).find('td');
      if (cells.length >= 2) {
        const label = $(cells[0]).text().trim();
        const value = $(cells[1]).text().trim();

        console.log(`Found table row: "${label}" = "${value}"`);

        switch (label) {
          case 'First Name':
            contactInfo.firstName = value;
            console.log(`✅ Set firstName: "${value}"`);
            break;
          case 'Last Name':
            contactInfo.lastName = value;
            console.log(`✅ Set lastName: "${value}"`);
            break;
          case 'Company Email':
          case 'Email':
            contactInfo.email = value;
            console.log(`✅ Set email: "${value}"`);
            break;
          case 'Phone':
            contactInfo.phone = value;
            console.log(`✅ Set phone: "${value}"`);
            break;
        }
      }
    });

    // Method 2: Look for any text patterns that match your format
    const firstNameMatch = ticketContent.match(/First\s+Name[:\s]+([^\s\n<]+)/i);
    const lastNameMatch = ticketContent.match(/Last\s+Name[:\s]+([^\s\n<]+)/i);
    const emailMatch = ticketContent.match(/(?:Company\s+Email|Email)[:\s]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    const phoneMatch = ticketContent.match(/Phone[:\s]+([\d\-\+\(\)\s]+)/i);

    if (firstNameMatch) contactInfo.firstName = firstNameMatch[1];
    if (lastNameMatch) contactInfo.lastName = lastNameMatch[1];
    if (emailMatch) contactInfo.email = emailMatch[1];
    if (phoneMatch) contactInfo.phone = phoneMatch[1].trim();

    // Method 3: Look for any email pattern in the content (but be more inclusive)
    if (!contactInfo.email) {
      const emailPattern = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
      const emails = ticketContent.match(emailPattern);
      if (emails && emails.length > 0) {
        // Filter out obvious system emails but keep customer emails
        const userEmail = emails.find(email => 
          !email.includes('zendesk.com') &&
          !email.includes('noreply') &&
          !email.includes('support@elotouch.com') &&
          !email.includes('roger.rhodes@elotouch.com')
        );
        if (userEmail) {
          contactInfo.email = userEmail;
        }
      }
    }

    // Method 4: Look for highlighted content (yellow background)
    $('[style*="background"], .highlight').each((index, element) => {
      const text = $(element).text().trim();
      console.log(`Found highlighted text: "${text}"`);
      
      if (text.includes('@') && !contactInfo.email) {
        contactInfo.email = text;
      }
    });

    console.log('Extracted contact info:', contactInfo);

  } catch (error) {
    console.error('Error extracting contact info:', error);
  }

  return contactInfo;
}

// Check if user exists in Zendesk
async function findUserByEmail(email) {
  try {
    const response = await axios.get(
      `${ZENDESK_DOMAIN}/api/v2/users/search.json?query=email:${encodeURIComponent(email)}`,
      { headers: getZendeskHeaders() }
    );
    
    return response.data.users.length > 0 ? response.data.users[0] : null;
  } catch (error) {
    console.error('Error searching for user:', error.response?.data || error.message);
    return null;
  }
}

// Format phone number to E.164 format
function formatPhoneNumber(phone) {
  if (!phone) return null;
  
  // Remove all non-digit characters
  const digitsOnly = phone.replace(/\D/g, '');
  
  // Only process US numbers that we're confident about
  // If it's already 11 digits starting with 1, format as US number
  if (digitsOnly.length === 11 && digitsOnly.startsWith('1')) {
    const areaCode = digitsOnly.slice(1, 4);
    const exchange = digitsOnly.slice(4, 7);
    const number = digitsOnly.slice(7);
    return `+1 (${areaCode}) ${exchange}-${number}`;
  }
  
  // If it's 10 digits and looks like a valid US number
  if (digitsOnly.length === 10) {
    const areaCode = digitsOnly.slice(0, 3);
    // Only format if it looks like a valid US area code
    if (areaCode >= '200' && areaCode <= '999' && !areaCode.startsWith('0') && !areaCode.startsWith('1')) {
      const exchange = digitsOnly.slice(3, 6);
      const number = digitsOnly.slice(6);
      return `+1 (${areaCode}) ${exchange}-${number}`;
    }
  }
  
  // For any other format, skip the phone field to avoid validation errors
  console.log(`Phone number "${phone}" doesn't match US format, skipping phone field to avoid validation errors`);
  return null;
}

// Create new user in Zendesk
async function createUser(contactInfo) {
  try {
    const userData = {
      user: {
        name: `${contactInfo.firstName} ${contactInfo.lastName}`.trim(),
        email: contactInfo.email,
        role: 'end-user',
        verified: true
      }
    };

    // Only add phone if it can be properly formatted
    if (contactInfo.phone) {
      const formattedPhone = formatPhoneNumber(contactInfo.phone);
      if (formattedPhone) {
        userData.user.phone = formattedPhone;
        console.log(`Formatted phone: "${contactInfo.phone}" → "${formattedPhone}"`);
      }
    }

    console.log('Attempting to create user with data:', JSON.stringify(userData, null, 2));

    const response = await axios.post(
      `${ZENDESK_DOMAIN}/api/v2/users/create_or_update.json`,
      userData,
      { headers: getZendeskHeaders() }
    );

    console.log('Created/updated user:', response.data.user.id);
    return response.data.user;
  } catch (error) {
    console.error('Error creating user - Status:', error.response?.status);
    console.error('Error creating user - Data:', JSON.stringify(error.response?.data, null, 2));
    console.error('Error creating user - Message:', error.message);
    throw error;
  }
}

// Update ticket with requestor and group assignment (but keep it open for macro)
async function updateTicketRequestor(ticketId, userId) {
  try {
    const updateData = {
      ticket: {
        requester_id: userId,
        assignee_id: null, // Remove individual assignee
        group_id: parseInt(TARGET_GROUP_ID), // Assign to "Elo Technical Support" group
        additional_tags: [PROCESSED_TAG],
        comment: {
          body: 'Contact information processed and user assigned automatically for cancellation response.',
          public: false
        }
      }
    };

    console.log('Attempting to update ticket requestor with data:', JSON.stringify(updateData, null, 2));

    const response = await axios.put(
      `${ZENDESK_DOMAIN}/api/v2/tickets/${ticketId}.json`,
      updateData,
      { headers: getZendeskHeaders() }
    );

    console.log(`Updated ticket ${ticketId} with requestor ${userId} and assigned to group`);
    return response.data.ticket;
  } catch (error) {
    console.error('Error updating ticket requestor - Status:', error.response?.status);
    console.error('Error updating ticket requestor - Data:', JSON.stringify(error.response?.data, null, 2));
    console.error('Error updating ticket requestor - Message:', error.message);
    throw error;
  }
}

// Close ticket after macro is applied
async function closeTicket(ticketId) {
  try {
    const updateData = {
      ticket: {
        status: 'closed', // Use 'closed' instead of 'solved' to prevent reopening
        comment: {
          body: 'EV Expiration email sent. This ticket has been solved and closed.',
          public: false
        }
      }
    };

    console.log('Attempting to close ticket with data:', JSON.stringify(updateData, null, 2));

    const response = await axios.put(
      `${ZENDESK_DOMAIN}/api/v2/tickets/${ticketId}.json`,
      updateData,
      { headers: getZendeskHeaders() }
    );

    console.log(`Closed ticket ${ticketId}`);
    return response.data.ticket;
  } catch (error) {
    console.error('Error closing ticket - Status:', error.response?.status);
    console.error('Error closing ticket - Data:', JSON.stringify(error.response?.data, null, 2));
    console.error('Error closing ticket - Message:', error.message);
    throw error;
  }
}

// Check if macro exists
async function verifyMacro(macroId) {
  try {
    const response = await axios.get(
      `${ZENDESK_DOMAIN}/api/v2/macros/${macroId}.json`,
      { headers: getZendeskHeaders() }
    );
    
    console.log(`Macro ${macroId} exists: "${response.data.macro.title}"`);
    return response.data.macro;
  } catch (error) {
    console.error(`Macro ${macroId} not found:`, error.response?.data || error.message);
    return null;
  }
}

// Apply macro to ticket and execute its actions
async function applyMacro(ticketId, macroId) {
  try {
    console.log(`Getting macro ${macroId} details first...`);
    
    // First, get the macro to see what it contains
    const macroResponse = await axios.get(
      `${ZENDESK_DOMAIN}/api/v2/macros/${macroId}.json`,
      { headers: getZendeskHeaders() }
    );
    
    const macro = macroResponse.data.macro;
    console.log(`Macro "${macro.title}" has ${macro.actions.length} actions`);
    
    // Try to execute the macro using the show endpoint and apply
    try {
      console.log(`Attempting to execute macro ${macroId} on ticket ${ticketId}...`);
      
      const executeResponse = await axios.get(
        `${ZENDESK_DOMAIN}/api/v2/tickets/${ticketId}/macros/${macroId}/apply.json`,
        { headers: getZendeskHeaders() }
      );
      
      // Now apply the result
      if (executeResponse.data && executeResponse.data.result) {
        const result = executeResponse.data.result;
        console.log('Applying macro execution result...');
        
        const applyResponse = await axios.put(
          `${ZENDESK_DOMAIN}/api/v2/tickets/${ticketId}.json`,
          { ticket: result.ticket },
          { headers: getZendeskHeaders() }
        );
        
        console.log(`✅ Successfully executed and applied macro ${macroId} to ticket ${ticketId}`);
        return applyResponse.data;
      }
    } catch (executeError) {
      console.log('Macro execution failed, manually applying macro actions...');
    }
    
    // Manual application - extract and apply each action
    const updateData = {
      ticket: {}
    };
    
    let hasComment = false;
    
    macro.actions.forEach(action => {
      console.log(`Processing macro action: ${action.field} = ${action.value}`);
      
      switch (action.field) {
        case 'comment_value':
        case 'comment_value_html':
          updateData.ticket.comment = {
            body: action.value,
            public: true,
            html_body: action.field === 'comment_value_html' ? action.value : undefined
          };
          hasComment = true;
          console.log(`Adding comment from macro: ${action.value.substring(0, 100)}...`);
          break;
        case 'status':
          updateData.ticket.status = action.value;
          console.log(`Setting status from macro to: ${action.value}`);
          break;
        case 'priority':
          updateData.ticket.priority = action.value;
          break;
        case 'type':
          updateData.ticket.type = action.value;
          break;
        case 'group_id':
          updateData.ticket.group_id = action.value;
          break;
        case 'assignee_id':
          updateData.ticket.assignee_id = action.value;
          break;
        default:
          console.log(`Unknown macro action field: ${action.field}`);
      }
    });
    
    if (Object.keys(updateData.ticket).length === 0) {
      console.log(`⚠️ No applicable actions found in macro ${macroId}`);
      return null;
    }
    
    console.log('Applying macro actions:', JSON.stringify(updateData, null, 2));
    
    const response = await axios.put(
      `${ZENDESK_DOMAIN}/api/v2/tickets/${ticketId}.json`,
      updateData,
      { headers: getZendeskHeaders() }
    );
    
    console.log(`✅ Successfully applied macro ${macroId} actions to ticket ${ticketId}`);
    if (hasComment) {
      console.log('✅ Macro comment/email content has been posted to the ticket');
    }
    
    return response.data;
    
  } catch (error) {
    console.error('❌ Failed to apply macro:', error.response?.data || error.message);
    throw error;
  }
}

// Get ticket details
async function getTicketDetails(ticketId) {
  try {
    const response = await axios.get(
      `${ZENDESK_DOMAIN}/api/v2/tickets/${ticketId}.json?include=comments`,
      { headers: getZendeskHeaders() }
    );
    
    return response.data.ticket;
  } catch (error) {
    console.error('Error getting ticket details:', error.response?.data || error.message);
    throw error;
  }
}

// Main processing function for cancellation tickets
async function processTicket(ticketId) {
  try {
    console.log(`Processing cancellation ticket ${ticketId}`);

    // Check in-memory cache first (fast check for rapid duplicate webhooks)
    if (recentlyProcessed.has(ticketId)) {
      console.log(`Ticket ${ticketId} was recently processed, skipping (in-memory cache)`);
      return { success: false, reason: 'Recently processed (cooldown)' };
    }

    // Get ticket details
    const ticket = await getTicketDetails(ticketId);

    // Check if ticket has the target tag
    if (!ticket.tags.includes(TARGET_TAG)) {
      console.log(`Ticket ${ticketId} doesn't have ${TARGET_TAG} tag, skipping`);
      return { success: false, reason: 'Missing target tag' };
    }

    // Check if already processed
    if (ticket.tags.includes(PROCESSED_TAG)) {
      console.log(`Ticket ${ticketId} already has ${PROCESSED_TAG} tag, skipping`);
      return { success: false, reason: 'Already processed' };
    }

    // Check if ticket has the target subject
    if (!ticket.subject || !ticket.subject.includes(TARGET_SUBJECT)) {
      console.log(`Ticket ${ticketId} doesn't have subject "${TARGET_SUBJECT}", skipping`);
      console.log(`Current subject: "${ticket.subject}"`);
      return { success: false, reason: 'Missing target subject' };
    }

    console.log(`✅ Ticket ${ticketId} matches criteria - Tag: ${TARGET_TAG}, Subject contains: "${TARGET_SUBJECT}"`);

    // Mark as being processed in memory cache
    recentlyProcessed.set(ticketId, Date.now());

    // Extract contact information from ticket description and comments
    let ticketContent = ticket.description || '';
    
    // Also check comments for contact info
    if (ticket.comments && ticket.comments.length > 0) {
      ticketContent += ' ' + ticket.comments.map(comment => comment.html_body || comment.body).join(' ');
    }

    const contactInfo = extractContactInfo(ticketContent);

    // Validate required information
    if (!contactInfo.email) {
      console.log(`No email found in ticket ${ticketId}`);
      return { success: false, reason: 'No email found' };
    }

    if (!contactInfo.firstName && !contactInfo.lastName) {
      console.log(`No name found in ticket ${ticketId}`);
      return { success: false, reason: 'No name found' };
    }

    console.log('Extracted contact info:', contactInfo);

    // Check if user already exists
    let user = await findUserByEmail(contactInfo.email);
    
    if (!user) {
      // Create new user
      user = await createUser(contactInfo);
      console.log(`Created new user: ${user.id} (${user.email})`);
    } else {
      console.log(`User already exists: ${user.id} (${user.email})`);
    }

    // STEP 1: Update ticket with user as requestor FIRST
    console.log('Step 1: Setting ticket requestor to ensure macro email goes to correct recipient...');
    await updateTicketRequestor(ticketId, user.id);

    // STEP 2: Apply the cancellation macro (now that the requestor is set correctly)
    try {
      const macro = await verifyMacro(MACRO_ID);
      if (macro) {
        console.log('Step 2: Applying cancellation macro with correct requestor...');
        await applyMacro(ticketId, MACRO_ID);
        console.log('✅ Cancellation macro applied successfully - email should go to customer');
      } else {
        console.log(`Warning: Macro ${MACRO_ID} not found, skipping macro application`);
      }
    } catch (macroError) {
      console.log(`Warning: Could not apply macro ${MACRO_ID}:`, macroError.message);
      // Continue even if macro fails
    }

    // STEP 3: Close the ticket (optional - the macro might already do this)
    console.log('Step 3: Closing ticket...');
    await closeTicket(ticketId);

    return {
      success: true,
      userId: user.id,
      userEmail: user.email,
      contactInfo: contactInfo,
      type: 'cancellation'
    };

  } catch (error) {
    console.error(`Error processing cancellation ticket ${ticketId}:`, error);
    return { success: false, reason: error.message };
  }
}

// Webhook endpoint for Zendesk
app.post('/webhook/zendesk', verifyZendeskSignature, async (req, res) => {
  try {
    console.log('Received webhook:', JSON.stringify(req.body, null, 2));

    const rawId = req.body.ticket?.id;
    const ticketId = parseInt(rawId, 10);

    if (!rawId || isNaN(ticketId) || ticketId <= 0) {
      return res.status(400).json({ error: 'Invalid or missing ticket ID' });
    }

    const result = await processTicket(ticketId);

    res.json({
      success: result.success,
      ticketId: ticketId,
      result: result
    });

  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Manual processing endpoint (admin only)
app.post('/process-ticket/:ticketId', verifyAdminSecret, async (req, res) => {
  try {
    const ticketId = parseInt(req.params.ticketId, 10);

    if (isNaN(ticketId) || ticketId <= 0) {
      return res.status(400).json({ error: 'Invalid ticket ID' });
    }

    const result = await processTicket(ticketId);

    res.json({
      success: result.success,
      ticketId: ticketId,
      result: result
    });

  } catch (error) {
    console.error('Manual processing error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Test macro endpoint (admin only)
app.get('/test-macro/:macroId', verifyAdminSecret, async (req, res) => {
  try {
    const macroId = parseInt(req.params.macroId, 10);

    if (isNaN(macroId) || macroId <= 0) {
      return res.status(400).json({ error: 'Invalid macro ID' });
    }

    const response = await axios.get(
      `${ZENDESK_DOMAIN}/api/v2/macros/${macroId}.json`,
      { headers: getZendeskHeaders() }
    );

    const macro = response.data.macro;

    res.json({
      success: true,
      macro: {
        id: macro.id,
        title: macro.title,
        active: macro.active,
        actions: macro.actions,
        description: macro.description
      }
    });
  } catch (error) {
    console.error('Test macro error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Start server
const PORT = process.env.PORT || 3001; // Different port from the welcome app

console.log('🔧 Attempting to start server on port:', PORT);

app.listen(PORT, () => {
  console.log(`✅ Zendesk EV Cancellation Handler running on port ${PORT}`);
  console.log(`🌐 Webhook endpoint: http://localhost:${PORT}/webhook/zendesk`);
  console.log(`🔧 Manual processing: http://localhost:${PORT}/process-ticket/{ticketId}`);
  console.log(`🎯 Target criteria: Tag="${TARGET_TAG}" AND Subject contains "${TARGET_SUBJECT}"`);
}).on('error', (err) => {
  console.error('❌ Server failed to start:', err);
  process.exit(1);
});

console.log('📝 Server setup complete, waiting for connections...');

module.exports = app;
