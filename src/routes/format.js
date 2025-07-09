const express = require('express');
const multer = require('multer');
const yaml = require('js-yaml');
const { basicRateLimit } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

// Helper function to validate YAML syntax before parsing
function validateYamlSyntax(yamlString) {
  const errors = [];
  const lines = yamlString.split('\n');

  // Check for basic YAML syntax issues
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Skip empty lines and comments
    if (!line.trim() || line.trim().startsWith('#')) continue;

    // Check for tabs (YAML doesn't allow tabs for indentation)
    if (line.includes('\t')) {
      errors.push(`Line ${lineNum}: YAML doesn't allow tabs for indentation, use spaces only`);
    }

    // Check for inconsistent indentation
    if (line.match(/^\s+/) && line.match(/^\s+/)[0].length % 2 !== 0) {
      const leadingSpaces = line.match(/^\s+/)[0].length;
      if (leadingSpaces > 0 && leadingSpaces % 2 !== 0) {
        errors.push(`Line ${lineNum}: Inconsistent indentation (${leadingSpaces} spaces), use even numbers of spaces`);
      }
    }

    // Check for common YAML mistakes
    if (line.includes(': ') && line.includes('  :')) {
      errors.push(`Line ${lineNum}: Extra spaces before colon`);
    }

    // Check for unquoted strings that might cause issues
    const colonMatch = line.match(/:\s*(.+)$/);
    if (colonMatch) {
      const value = colonMatch[1].trim();
      if (value && !value.startsWith('"') && !value.startsWith("'") &&
        (value.includes(':') || value.includes('[') || value.includes('{') ||
          value.includes('|') || value.includes('>'))) {
        errors.push(`Line ${lineNum}: Complex value should be quoted: "${value}"`);
      }
    }
  }

  return errors;
}

// Helper function to validate JSON syntax before parsing
function validateJsonSyntax(jsonString) {
  const errors = [];

  // Check for basic JSON structure
  const trimmed = jsonString.trim();

  // JSON must start with { or [
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    errors.push('JSON must start with { or [');
  }

  // JSON must end with } or ]
  if (!trimmed.endsWith('}') && !trimmed.endsWith(']')) {
    errors.push('JSON must end with } or ]');
  }

  // Check for common mistakes
  if (trimmed.includes("'")) {
    errors.push('JSON strings must use double quotes, not single quotes');
  }

  // Check for trailing commas (common mistake)
  if (trimmed.match(/,\s*[}\]]/)) {
    errors.push('JSON cannot have trailing commas');
  }

  // FIXED: Better unquoted key detection
  // Look for patterns like: word: (without quotes around the key)
  // But avoid false positives with properly quoted keys
  const lines = trimmed.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('//') || line.startsWith('/*')) continue;

    // Look for unquoted keys: word: or word : (not "word":)
    const unquotedKeyMatch = line.match(/^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*/);
    if (unquotedKeyMatch && !line.match(/^\s*"[^"]*"\s*:\s*/)) {
      errors.push(`Unquoted key detected: "${unquotedKeyMatch[1]}" - JSON keys must be quoted`);
      break; // Only report the first one to avoid spam
    }
  }

  return errors;
}

const router = express.Router();

// Configure multer for text file uploads
const uploadText = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow JSON, YAML, YML, and text files
    const allowedTypes = [
      'application/json',
      'text/plain',
      'application/x-yaml',
      'text/yaml',
      'text/x-yaml'
    ];

    const allowedExtensions = ['.json', '.yaml', '.yml', '.txt'];
    const hasValidExtension = allowedExtensions.some(ext =>
      file.originalname.toLowerCase().endsWith(ext)
    );

    if (allowedTypes.includes(file.mimetype) || hasValidExtension) {
      cb(null, true);
    } else {
      cb(new Error('File must be JSON, YAML, YML, or text file'), false);
    }
  }
});

/**
 * POST /api/format/yaml-to-json
 * Convert YAML data to JSON format
 */
router.post('/yaml-to-json', enhancedSecurityWithRateLimit(basicRateLimit), uploadText.single('file'), async (req, res) => {
  try {
    let yamlData;

    // Get YAML data from file upload or request body
    if (req.file) {
      yamlData = req.file.buffer.toString('utf8');
      logger.info('Processing YAML file upload', {
        originalName: req.file.originalname,
        fileSize: req.file.buffer.length,
        mimetype: req.file.mimetype
      });
    } else if (req.body.yamlData) {
      yamlData = req.body.yamlData;
      logger.info('Processing YAML data from request body', {
        dataLength: yamlData.length
      });
    } else {
      return sendError(res, 'No YAML data provided. Please upload a file or provide YAML data in request body.', 400);
    }

    if (!yamlData || yamlData.trim().length === 0) {
      return sendError(res, 'YAML data is empty', 400);
    }

    const indentSize = parseInt(req.body.indentSize) || 2;

    // Validate indent size
    if (indentSize < 0 || indentSize > 8) {
      return sendError(res, 'Indent size must be between 0 and 8', 400);
    }

    logger.info('Starting YAML to JSON conversion', {
      dataLength: yamlData.length,
      indentSize,
      source: req.file ? 'file' : 'body'
    });

    try {
      // Pre-validate YAML structure for common issues
      const trimmedYaml = yamlData.trim();

      // Check for empty YAML
      if (!trimmedYaml) {
        return sendError(res, 'YAML data is empty or contains only whitespace', 400, {
          yamlError: 'Empty input',
          suggestion: 'Please provide valid YAML content'
        });
      }

      // Check for common YAML syntax issues
      const yamlValidationErrors = validateYamlSyntax(trimmedYaml);
      if (yamlValidationErrors.length > 0) {
        logger.warn('YAML syntax validation failed', {
          errors: yamlValidationErrors,
          source: req.file ? req.file.originalname : 'request body'
        });

        // Format multiple errors for better display
        const primaryError = yamlValidationErrors[0];
        const allErrorsText = yamlValidationErrors.length > 1
          ? `\n\nAll issues found:\n${yamlValidationErrors.map((err, i) => `${i + 1}. ${err}`).join('\n')}`
          : '';

        return sendError(res, `Invalid YAML syntax: ${primaryError}${allErrorsText}`, 400, {
          yamlError: primaryError,
          allErrors: yamlValidationErrors,
          suggestion: 'Please check your YAML formatting and fix syntax errors'
        });
      }

      // Parse YAML to JavaScript object with enhanced error handling
      const parsedData = yaml.load(yamlData, {
        onWarning: (warning) => {
          logger.warn('YAML parsing warning', {
            warning: warning.toString(),
            source: req.file ? req.file.originalname : 'request body'
          });
        },
        // Prevent prototype pollution
        json: true,
        // Schema validation
        schema: yaml.DEFAULT_SCHEMA
      });

      // Validate parsed data
      if (parsedData === undefined) {
        return sendError(res, 'YAML parsing resulted in undefined data', 400, {
          yamlError: 'Undefined result',
          suggestion: 'YAML may be empty or contain only comments'
        });
      }

      // Check for circular references before JSON conversion
      try {
        JSON.stringify(parsedData);
      } catch (circularError) {
        logger.error('Circular reference detected in parsed YAML', {
          error: circularError.message,
          source: req.file ? req.file.originalname : 'request body'
        });

        return sendError(res, 'YAML contains circular references that cannot be converted to JSON', 400, {
          yamlError: 'Circular reference detected',
          suggestion: 'Remove circular references from your YAML data'
        });
      }

      // Convert to JSON string
      const jsonString = indentSize === 0
        ? JSON.stringify(parsedData)
        : JSON.stringify(parsedData, null, indentSize);

      // Validate JSON output
      if (!jsonString || jsonString === 'null') {
        return sendError(res, 'YAML conversion resulted in invalid JSON output', 400, {
          yamlError: 'Invalid JSON result',
          suggestion: 'YAML structure may not be compatible with JSON format'
        });
      }

      // Calculate conversion statistics
      const originalLines = yamlData.split('\n').length;
      const convertedLines = jsonString.split('\n').length;

      logger.info('YAML to JSON conversion completed successfully', {
        originalLines,
        convertedLines,
        originalSize: yamlData.length,
        convertedSize: jsonString.length,
        indentSize,
        dataType: typeof parsedData,
        isArray: Array.isArray(parsedData),
        source: req.file ? req.file.originalname : 'request body'
      });

      // Send success response
      return sendSuccess(res, 'YAML successfully converted to JSON', {
        data: jsonString,
        metadata: {
          originalLines,
          convertedLines,
          originalSize: yamlData.length,
          convertedSize: jsonString.length,
          indentSize,
          dataType: typeof parsedData,
          isArray: Array.isArray(parsedData),
          timestamp: new Date().toISOString()
        }
      });

    } catch (yamlError) {
      // Enhanced error logging and user-friendly messages
      const errorDetails = {
        error: yamlError.message,
        name: yamlError.name,
        dataLength: yamlData.length,
        source: req.file ? req.file.originalname : 'request body',
        line: yamlError.mark?.line ? yamlError.mark.line + 1 : undefined,
        column: yamlError.mark?.column ? yamlError.mark.column + 1 : undefined,
        position: yamlError.mark?.position
      };

      logger.error('YAML parsing error', errorDetails);

      // Create user-friendly error message
      let userMessage = 'Invalid YAML format';
      let suggestion = 'Please check your YAML syntax and fix any formatting errors';

      if (yamlError.name === 'YAMLException') {
        if (yamlError.message.includes('duplicated mapping key')) {
          userMessage = 'YAML contains duplicate keys';
          suggestion = 'Remove or rename duplicate keys in your YAML';
        } else if (yamlError.message.includes('bad indentation')) {
          userMessage = 'YAML has incorrect indentation';
          suggestion = 'Fix indentation issues - use consistent spaces (not tabs)';
        } else if (yamlError.message.includes('unexpected end of the stream')) {
          userMessage = 'YAML is incomplete or truncated';
          suggestion = 'Ensure your YAML document is complete';
        } else if (yamlError.message.includes('expected a single document')) {
          userMessage = 'YAML contains multiple documents';
          suggestion = 'This tool supports single YAML documents only';
        } else {
          userMessage = `YAML parsing failed: ${yamlError.message}`;
        }
      }

      // Add line/column info if available
      if (yamlError.mark?.line !== undefined) {
        userMessage += ` (line ${yamlError.mark.line + 1}`;
        if (yamlError.mark.column !== undefined) {
          userMessage += `, column ${yamlError.mark.column + 1}`;
        }
        userMessage += ')';
      }

      return sendError(res, userMessage, 400, {
        yamlError: yamlError.message,
        errorName: yamlError.name,
        line: yamlError.mark?.line ? yamlError.mark.line + 1 : undefined,
        column: yamlError.mark?.column ? yamlError.mark.column + 1 : undefined,
        suggestion: suggestion
      });
    }

  } catch (error) {
    logger.error('YAML to JSON conversion error:', {
      error: error.message,
      stack: error.stack,
      hasFile: !!req.file,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be')) {
      return sendError(res, error.message, 400);
    }

    return sendError(res, 'Failed to convert YAML to JSON', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/format/json-to-yaml
 * Convert JSON data to YAML format
 */
router.post('/json-to-yaml', enhancedSecurityWithRateLimit(basicRateLimit), uploadText.single('file'), async (req, res) => {
  try {
    let jsonData;

    // Get JSON data from file upload or request body
    if (req.file) {
      jsonData = req.file.buffer.toString('utf8');
      logger.info('Processing JSON file upload', {
        originalName: req.file.originalname,
        fileSize: req.file.buffer.length,
        mimetype: req.file.mimetype
      });
    } else if (req.body.jsonData) {
      jsonData = req.body.jsonData;
      logger.info('Processing JSON data from request body', {
        dataLength: jsonData.length
      });
    } else {
      return sendError(res, 'No JSON data provided. Please upload a file or provide JSON data in request body.', 400);
    }

    if (!jsonData || jsonData.trim().length === 0) {
      return sendError(res, 'JSON data is empty', 400);
    }

    const indentSize = parseInt(req.body.indentSize) || 2;
    const flowLevel = parseInt(req.body.flowLevel) || -1;

    // Validate parameters
    if (indentSize < 2 || indentSize > 8) {
      return sendError(res, 'Indent size must be between 2 and 8', 400);
    }

    if (flowLevel < -1 || flowLevel > 5) {
      return sendError(res, 'Flow level must be between -1 and 5', 400);
    }

    logger.info('Starting JSON to YAML conversion', {
      dataLength: jsonData.length,
      indentSize,
      flowLevel,
      source: req.file ? 'file' : 'body'
    });

    try {
      // Pre-validate JSON structure
      const trimmedJson = jsonData.trim();

      // Check for empty JSON
      if (!trimmedJson) {
        return sendError(res, 'JSON data is empty or contains only whitespace', 400, {
          jsonError: 'Empty input',
          suggestion: 'Please provide valid JSON content'
        });
      }

      // Skip pre-validation for JSON - let JSON.parse() handle it more reliably
      // The native parser is better at detecting actual JSON syntax issues

      // Parse JSON to JavaScript object with enhanced error handling
      let parsedData;
      try {
        parsedData = JSON.parse(jsonData);
      } catch (parseError) {
        logger.error('JSON parsing error', {
          error: parseError.message,
          dataLength: jsonData.length,
          source: req.file ? req.file.originalname : 'request body'
        });

        // Create user-friendly error message
        let userMessage = 'Invalid JSON format';
        let suggestion = 'Please check your JSON syntax and fix any formatting errors';

        if (parseError.message.includes('Unexpected token')) {
          const match = parseError.message.match(/Unexpected token (.) in JSON at position (\d+)/);
          if (match) {
            const [, token, position] = match;
            const pos = parseInt(position);
            const lines = jsonData.substring(0, pos).split('\n');
            const line = lines.length;
            const column = lines[lines.length - 1].length + 1;

            userMessage = `Invalid JSON: Unexpected character '${token}' at line ${line}, column ${column}`;
            suggestion = 'Check for missing quotes, commas, or brackets';
          }
        } else if (parseError.message.includes('Unexpected end of JSON input')) {
          userMessage = 'JSON is incomplete or truncated';
          suggestion = 'Ensure your JSON document is complete with proper closing brackets/braces';
        } else if (parseError.message.includes('duplicate key')) {
          userMessage = 'JSON contains duplicate keys';
          suggestion = 'Remove or rename duplicate keys in your JSON';
        }

        return sendError(res, userMessage, 400, {
          jsonError: parseError.message,
          suggestion: suggestion
        });
      }

      // Validate parsed data
      if (parsedData === undefined) {
        return sendError(res, 'JSON parsing resulted in undefined data', 400, {
          jsonError: 'Undefined result',
          suggestion: 'JSON content may be invalid'
        });
      }

      // Check for functions or other non-serializable content
      try {
        // Test if data can be safely converted to YAML
        const testJson = JSON.stringify(parsedData);
        JSON.parse(testJson); // Ensure round-trip works
      } catch (serializationError) {
        logger.error('JSON serialization test failed', {
          error: serializationError.message,
          source: req.file ? req.file.originalname : 'request body'
        });

        return sendError(res, 'JSON contains data that cannot be converted to YAML', 400, {
          jsonError: 'Serialization failed',
          suggestion: 'Ensure JSON contains only basic data types (strings, numbers, booleans, arrays, objects)'
        });
      }

      // Configure YAML dump options
      const yamlOptions = {
        indent: indentSize,
        lineWidth: -1, // Don't wrap lines
        noRefs: true, // Don't use references
        skipInvalid: false,
        sortKeys: false,
        flowLevel: flowLevel === -1 ? undefined : flowLevel
      };

      // Special handling for different flow levels
      if (flowLevel === 0) {
        yamlOptions.flowLevel = 0; // All flow style
      } else if (flowLevel === 1) {
        yamlOptions.flowLevel = 1; // Arrays in flow style
      }

      // Convert to YAML string with error handling
      let yamlString;
      try {
        yamlString = yaml.dump(parsedData, yamlOptions);
      } catch (yamlError) {
        logger.error('YAML generation error', {
          error: yamlError.message,
          source: req.file ? req.file.originalname : 'request body'
        });

        return sendError(res, `Failed to convert JSON to YAML: ${yamlError.message}`, 500, {
          yamlError: yamlError.message,
          suggestion: 'The JSON structure may be too complex for YAML conversion'
        });
      }

      // Validate YAML output
      if (!yamlString || yamlString.trim() === '') {
        return sendError(res, 'JSON conversion resulted in empty YAML output', 400, {
          yamlError: 'Empty YAML result',
          suggestion: 'JSON structure may not be compatible with YAML format'
        });
      }

      // Test YAML output by parsing it back
      try {
        yaml.load(yamlString);
      } catch (yamlValidationError) {
        logger.error('Generated YAML validation failed', {
          error: yamlValidationError.message,
          source: req.file ? req.file.originalname : 'request body'
        });

        return sendError(res, 'Generated YAML is invalid', 500, {
          yamlError: yamlValidationError.message,
          suggestion: 'There may be an issue with the conversion process'
        });
      }

      // Calculate conversion statistics
      const originalLines = jsonData.split('\n').length;
      const convertedLines = yamlString.split('\n').length;

      logger.info('JSON to YAML conversion completed successfully', {
        originalLines,
        convertedLines,
        originalSize: jsonData.length,
        convertedSize: yamlString.length,
        indentSize,
        flowLevel,
        dataType: typeof parsedData,
        isArray: Array.isArray(parsedData),
        source: req.file ? req.file.originalname : 'request body'
      });

      // Send success response
      return sendSuccess(res, 'JSON successfully converted to YAML', {
        data: yamlString,
        metadata: {
          originalLines,
          convertedLines,
          originalSize: jsonData.length,
          convertedSize: yamlString.length,
          indentSize,
          flowLevel,
          dataType: typeof parsedData,
          isArray: Array.isArray(parsedData),
          timestamp: new Date().toISOString()
        }
      });

    } catch (jsonError) {
      logger.error('JSON to YAML conversion error', {
        error: jsonError.message,
        stack: jsonError.stack,
        dataLength: jsonData.length,
        source: req.file ? req.file.originalname : 'request body'
      });

      return sendError(res, `Invalid JSON format: ${jsonError.message}`, 400, {
        jsonError: jsonError.message
      });
    }

  } catch (error) {
    logger.error('JSON to YAML conversion error:', {
      error: error.message,
      stack: error.stack,
      hasFile: !!req.file,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be')) {
      return sendError(res, error.message, 400);
    }

    return sendError(res, 'Failed to convert JSON to YAML', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/format/yaml-to-json-batch
 * Convert multiple YAML files to JSON
 */
router.post('/yaml-to-json-batch', enhancedSecurityWithRateLimit(basicRateLimit), uploadText.array('files', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return sendError(res, 'No files provided', 400);
    }

    const indentSize = parseInt(req.body.indentSize) || 2;
    const results = [];
    const errors = [];

    logger.info('Starting batch YAML to JSON conversion', {
      fileCount: req.files.length,
      indentSize
    });

    // Process each file
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];

      try {
        const yamlData = file.buffer.toString('utf8');
        const originalName = file.originalname.replace(/\.(yaml|yml)$/i, '');

        // Parse YAML and convert to JSON
        const parsedData = yaml.load(yamlData, {
          onWarning: (warning) => {
            logger.warn('YAML parsing warning during batch processing', {
              warning: warning.toString(),
              filename: file.originalname
            });
          },
          json: true,
          schema: yaml.DEFAULT_SCHEMA
        });

        // Validate parsed data
        if (parsedData === undefined) {
          throw new Error('YAML parsing resulted in undefined data');
        }

        // Test JSON conversion
        const jsonString = indentSize === 0
          ? JSON.stringify(parsedData)
          : JSON.stringify(parsedData, null, indentSize);

        if (!jsonString || jsonString === 'null') {
          throw new Error('YAML conversion resulted in invalid JSON output');
        }

        results.push({
          originalName: file.originalname,
          convertedName: `${originalName}.json`,
          originalSize: yamlData.length,
          convertedSize: jsonString.length,
          originalLines: yamlData.split('\n').length,
          convertedLines: jsonString.split('\n').length,
          dataType: typeof parsedData,
          isArray: Array.isArray(parsedData),
          data: jsonString
        });

      } catch (error) {
        errors.push({
          filename: file.originalname,
          error: error.message,
          type: error.name || 'ConversionError'
        });
      }
    }

    logger.info('Batch YAML to JSON conversion completed', {
      totalFiles: req.files.length,
      successful: results.length,
      failed: errors.length,
      indentSize
    });

    return sendSuccess(res, 'Batch YAML to JSON conversion completed', {
      results,
      errors,
      summary: {
        totalFiles: req.files.length,
        successful: results.length,
        failed: errors.length,
        indentSize
      }
    });

  } catch (error) {
    logger.error('Batch YAML to JSON conversion error:', {
      error: error.message,
      stack: error.stack,
      fileCount: req.files?.length
    });

    return sendError(res, 'Failed to process batch conversion', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/format/json-to-yaml-batch
 * Convert multiple JSON files to YAML
 */
router.post('/json-to-yaml-batch', enhancedSecurityWithRateLimit(basicRateLimit), uploadText.array('files', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return sendError(res, 'No files provided', 400);
    }

    const indentSize = parseInt(req.body.indentSize) || 2;
    const flowLevel = parseInt(req.body.flowLevel) || -1;
    const results = [];
    const errors = [];

    logger.info('Starting batch JSON to YAML conversion', {
      fileCount: req.files.length,
      indentSize,
      flowLevel
    });

    // Configure YAML options
    const yamlOptions = {
      indent: indentSize,
      lineWidth: -1,
      noRefs: true,
      skipInvalid: false,
      sortKeys: false,
      flowLevel: flowLevel === -1 ? undefined : flowLevel
    };

    // Process each file
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];

      try {
        const jsonData = file.buffer.toString('utf8');
        const originalName = file.originalname.replace(/\.json$/i, '');

        // Parse JSON and convert to YAML
        let parsedData;
        try {
          parsedData = JSON.parse(jsonData);
        } catch (parseError) {
          throw new Error(`Invalid JSON in ${file.originalname}: ${parseError.message}`);
        }

        // Validate parsed data
        if (parsedData === undefined) {
          throw new Error('JSON parsing resulted in undefined data');
        }

        // Convert to YAML with error handling
        let yamlString;
        try {
          yamlString = yaml.dump(parsedData, yamlOptions);
        } catch (yamlError) {
          throw new Error(`YAML generation failed: ${yamlError.message}`);
        }

        if (!yamlString || yamlString.trim() === '') {
          throw new Error('JSON conversion resulted in empty YAML output');
        }

        // Validate generated YAML
        try {
          yaml.load(yamlString);
        } catch (validationError) {
          throw new Error(`Generated YAML is invalid: ${validationError.message}`);
        }

        results.push({
          originalName: file.originalname,
          convertedName: `${originalName}.yaml`,
          originalSize: jsonData.length,
          convertedSize: yamlString.length,
          originalLines: jsonData.split('\n').length,
          convertedLines: yamlString.split('\n').length,
          dataType: typeof parsedData,
          isArray: Array.isArray(parsedData),
          data: yamlString
        });

      } catch (error) {
        errors.push({
          filename: file.originalname,
          error: error.message,
          type: error.name || 'ConversionError'
        });
      }
    }

    logger.info('Batch JSON to YAML conversion completed', {
      totalFiles: req.files.length,
      successful: results.length,
      failed: errors.length,
      indentSize,
      flowLevel
    });

    return sendSuccess(res, 'Batch JSON to YAML conversion completed', {
      results,
      errors,
      summary: {
        totalFiles: req.files.length,
        successful: results.length,
        failed: errors.length,
        indentSize,
        flowLevel
      }
    });

  } catch (error) {
    logger.error('Batch JSON to YAML conversion error:', {
      error: error.message,
      stack: error.stack,
      fileCount: req.files?.length
    });

    return sendError(res, 'Failed to process batch conversion', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/format/validate-yaml
 * Validate YAML syntax without conversion
 */
router.post('/validate-yaml', enhancedSecurityWithRateLimit(basicRateLimit), uploadText.single('file'), async (req, res) => {
  try {
    let yamlData;

    if (req.file) {
      yamlData = req.file.buffer.toString('utf8');
    } else if (req.body.yamlData) {
      yamlData = req.body.yamlData;
    } else {
      return sendError(res, 'No YAML data provided', 400);
    }

    logger.info('Validating YAML data', {
      dataLength: yamlData.length,
      source: req.file ? 'file' : 'body'
    });

    try {
      const parsedData = yaml.load(yamlData);

      return sendSuccess(res, 'YAML is valid', {
        valid: true,
        dataType: typeof parsedData,
        isArray: Array.isArray(parsedData),
        keys: typeof parsedData === 'object' && parsedData !== null
          ? Object.keys(parsedData).length
          : null,
        lines: yamlData.split('\n').length
      });

    } catch (yamlError) {
      logger.warn('YAML validation failed', {
        error: yamlError.message,
        line: yamlError.mark?.line,
        column: yamlError.mark?.column
      });

      return sendSuccess(res, 'YAML validation completed', {
        valid: false,
        error: yamlError.message,
        line: yamlError.mark?.line,
        column: yamlError.mark?.column
      });
    }

  } catch (error) {
    logger.error('YAML validation error:', error);
    return sendError(res, 'Failed to validate YAML', 500);
  }
});

/**
 * POST /api/format/validate-json
 * Validate JSON syntax without conversion
 */
router.post('/validate-json', enhancedSecurityWithRateLimit(basicRateLimit), uploadText.single('file'), async (req, res) => {
  try {
    let jsonData;

    if (req.file) {
      jsonData = req.file.buffer.toString('utf8');
    } else if (req.body.jsonData) {
      jsonData = req.body.jsonData;
    } else {
      return sendError(res, 'No JSON data provided', 400);
    }

    logger.info('Validating JSON data', {
      dataLength: jsonData.length,
      source: req.file ? 'file' : 'body'
    });

    try {
      const parsedData = JSON.parse(jsonData);

      return sendSuccess(res, 'JSON is valid', {
        valid: true,
        dataType: typeof parsedData,
        isArray: Array.isArray(parsedData),
        keys: typeof parsedData === 'object' && parsedData !== null
          ? Object.keys(parsedData).length
          : null,
        lines: jsonData.split('\n').length
      });

    } catch (jsonError) {
      logger.warn('JSON validation failed', {
        error: jsonError.message
      });

      return sendSuccess(res, 'JSON validation completed', {
        valid: false,
        error: jsonError.message
      });
    }

  } catch (error) {
    logger.error('JSON validation error:', error);
    return sendError(res, 'Failed to validate JSON', 500);
  }
});

/**
 * GET /api/format/info
 * Get format conversion service information
 */
router.get('/info', enhancedSecurityWithRateLimit(basicRateLimit), (req, res) => {
  const info = {
    service: 'Format Conversion API',
    version: '1.0.0',
    supportedConversions: [
      'YAML to JSON',
      'JSON to YAML',
      'YAML Validation',
      'JSON Validation'
    ],
    endpoints: {
      yaml_to_json: 'POST /api/format/yaml-to-json',
      json_to_yaml: 'POST /api/format/json-to-yaml',
      yaml_to_json_batch: 'POST /api/format/yaml-to-json-batch',
      json_to_yaml_batch: 'POST /api/format/json-to-yaml-batch',
      validate_yaml: 'POST /api/format/validate-yaml',
      validate_json: 'POST /api/format/validate-json',
      info: 'GET /api/format/info'
    },
    limits: {
      maxFileSize: '5MB',
      maxBatchFiles: 10,
      indentSizeRange: '0-8 (JSON), 2-8 (YAML)',
      flowLevelRange: '-1 to 5 (YAML only)'
    },
    features: {
      fileUpload: true,
      dataInBody: true,
      batchProcessing: true,
      syntaxValidation: true,
      customIndentation: true,
      yamlFlowControl: true
    }
  };

  sendSuccess(res, 'Format conversion service information', info);
});

module.exports = router;
