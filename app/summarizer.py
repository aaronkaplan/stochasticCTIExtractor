"""Langchain based summarizer"""

import os
# import pandas as pd
from typing import Union, Dict
from distutils.util import strtobool
import tempfile

import openai
from langchain.chat_models import ChatOpenAI
from langchain.llms import AzureOpenAI
from langchain.llms import TextGen
from langchain.chains import ConversationChain
from langchain.memory import ConversationBufferMemory
from langchain.prompts import ChatPromptTemplate
from langchain.prompts import PromptTemplate
from langchain.output_parsers import ResponseSchema
from langchain.output_parsers import StructuredOutputParser
from langchain.chains.summarize import load_summarize_chain
# from langchain.text_splitter import CharacterTextSplitter
# from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.text_splitter import TokenTextSplitter
# from langchain.docstore.document import Document
from langchain.document_loaders.text import TextLoader
# from langchain.document_loaders import BSHTMLLoader
# from langchain.chains.summarize import load_summarize_chain
# from langchain.chains import LLMChain
# from langchain.chains.mapreduce import MapReduceChain
from langchain.prompts import PromptTemplate

from app.misc import save_string_to_custom_temp_file


debug = True

from dotenv import load_dotenv, find_dotenv
_ = load_dotenv(find_dotenv()) # read local .env file

DRY_RUN = strtobool(os.environ['DRY_RUN'])
MAXLEN=16000
PROMPTLEN=500
SUMMARYLEN=1000
USE_AZURE = strtobool(os.environ['USE_AZURE'])
if USE_AZURE:
    ENGINE=os.environ['ENGINE']
    MODEL="gpt4-32k"
    MAXLEN=32000
else:
    ENGINE=None
    MODEL="gpt-3.5-16k"
    # MODEL="llama2"


openai.api_key = os.environ['OPENAI_API_KEY']


# ################################
# templates. FIXME these should move to a template DB
CTI_TEMPLATE_INFO_EXTRACTION = """\
For the following text, extract the following information: \
ThreatActor: who is the threat actor? Format as JSON string.\
TTPs: what tools, techniques and procedures (TTPs) are they using? Format as JSON list of strings.\
Targets: whom are they targetting? Format as JSON list of strings.\
IoCs: all DNS domain names, hashes, path names, process names, registry keys. Format as JSON list of strings.
Goals: what are the goals of the Threat Actor? Format as string.

Format the output as JSON with the following keys:
ThreatActor
Goals
TTPs
Targets
IoCs

text: {text}
"""


# CouldWeBeAffected: Are we (the EU Institions, Bodies and Agencies) affected by the threat? Is the Threat Actor targetting the EU Institions, Bodies and Agencies? Answer True if yes, False if not. Answer None if not known.
# ThreatActor: who is the threat actor? If multiple, make a JSON list of strings. Format as a JSON list of strings. Answer ['unknown'] if not known.

CTI_TEMPLATE_SUMMARIZATION = """\

ThreatActor: Who is the threat actor? If multiple, make a comma separated list. Format as a JSON string. Answer 'unknown' if not known.
AttributedCountry: which country is suppossedly behind this Threat Actor? Format as a single JSON string. Answer 'unknown' if not known.
Type: How would you classify the Threat or Threat Actor? Possible answers: 'Crimeware', 'Nation-state', 'Developments in IT Security', 'Hacktivism', 'Information Warfare', 'unknown'. If multiple, separate by comma. Format as single JSON string. Answer 'unknown' if not known."
Motivation: what is the motivation, what are the goals of the Threat Actor? One of 'Espionage', 'Sabotage', 'Financial', 'Propaganda', 'Other', 'unknown' . Format as a single JSON string. One sentence only. Answer 'unknown' if unknown.
ExecutiveSummary: a short 200 word summary of the contents of the report. Focus on the specifics of this report. Leave out the general descriptions. Format a a single JSON string.
CouldWeBeAffected: Is the Threat Actor targetting Europe or EU Institutions, Bodies or Agencies?  Answer True if yes, False if not. Answer None if not known.

Format the output as JSON with the following keys:
AI_ThreatActor
AI_AttributedCountry
AI_Type
AI_Motivation
AI_ExecutiveSummary
AI_CouldWeBeAffected

text: {text}

"""
# {format_instructions}

THREAT_ACTOR_SCHEMA="Who is the threat actor? If multiple, make a comma separated list. Format as a JSON string. Answer 'unknown' if not known."
ATTRIBUTEDCOUNTRY_SCHEMA="Which country is suppossedly behind this Threat Actor? Format as a single JSON string. Answer 'unknown' if not known."
TYPE_SCHEMA="How would you classify the Threat or Threat Actor? Possible answers: 'Crimeware', 'Nation-state', 'Developments in IT Security', 'Hacktivism', 'Information Warfare', 'unknown'. If multiple, separate by comma. Format as single JSON string. Answer 'unknown' if not known."
# MOTIVATION_SCHEMA="What is the motivation, what are the goals of the Threat Actor? Format as a single JSON string. One sentence only. Answer 'unknown' if unknown."
MOTIVATION_SCHEMA="What is the motivation, what are the goals of the Threat Actor? One of 'Espionage', 'Sabotage', 'Financial', 'Propaganda', 'Other', 'unknown' . Format as a single JSON string. One sentence only. Answer 'unknown' if unknown."
EXECUTIVESUMMARY_SCHEMA= "A short 200 word summary of the contents of the report. Focus on the specifics of this report. Leave out the general descriptions. Format a a single JSON string."
#COULD_WE_BE_AFFECTED_SCHEMA="Are we (the EU Institions, Bodies and Agencies) affected by the threat? Is the Threat Actor targetting the EU Institions, Bodies and Agencies? Answer True if yes, False if not. Answer None if not known."
COULD_WE_BE_AFFECTED_SCHEMA="Is the Threat Actor targetting Europe or EU Institutions, Bodies or Agencies?  Answer True if yes, False if not. Answer None if not known."
# COULD_WE_BE_AFFECTED_SCHEMA="Does the text say that the Threat Actor is targetting Europe or EU Institutions?  Answer True if yes, False if not. Answer None if not known."

ta_schema = ResponseSchema(name="AI_ThreatActor", description=THREAT_ACTOR_SCHEMA, type="string")
country_schema = ResponseSchema(name="AI_AttributedCountry", description=ATTRIBUTEDCOUNTRY_SCHEMA, type="string")
type_schema = ResponseSchema(name="AI_Type", description=TYPE_SCHEMA, type="string")
motivation_schema = ResponseSchema(name="AI_Motivation", description=MOTIVATION_SCHEMA, type="string")
executivesummary_schema = ResponseSchema(name="AI_ExecutiveSummary", description=EXECUTIVESUMMARY_SCHEMA, type="string")
could_we_be_affected = ResponseSchema(name="AI_CouldWeBeAffected", description=COULD_WE_BE_AFFECTED_SCHEMA, type="Union[boolean, None]")

response_schemas = [ta_schema, country_schema, type_schema, motivation_schema, executivesummary_schema, could_we_be_affected]


class Summarizer():
    """A summarizer class, using langchain and recursive summarization tricks."""

    def __init__(self):
        self.model = MODEL
        if USE_AZURE:
            self.llm = AzureOpenAI ( deployment_name=os.environ['ENGINE'], temperature=0.0)
        else:
            self.llm = ChatOpenAI(temperature=0.0)
        # self.llm = TextGen(model_url=os.environ['OPENAI_API_BASE'])
        self.memory = ConversationBufferMemory()
        self.conversation = ConversationChain(
            llm=self.llm,
            memory = self.memory,
            verbose=False
        )

        self.prompt_template_summarization = PromptTemplate.from_template(CTI_TEMPLATE_SUMMARIZATION)
        if debug:
            print(self.prompt_template_summarization)


    def summarize_via_openai(self, text: str) -> Dict:           # Union[None, str]:
        """
        Summarize the content of a given text using OpenAI's with chunking.

        Parameters:
        - text (str): A string containing the CTI report

        Returns:
        - str or None: Returns the summary of the content of the URL if successful. Returns None if the URL is invalid or if any exception occurs.

        Raises:
        - Exception: An exception is raised if there is any issue in loading the URL or during the summarization process. The exception's message is printed to the console.

        Notes:
        - If the variable DRY_RUN is set in the environment, nothing will be sent to  the llm
        - It utilizes a token text splitter (`TokenTextSplitter`) with specific chunk sizes and encoding for GPT-3 to split the content into manageable pieces.
        - Summarization is done using a "map-reduce" chain for processing the chunks of text. The prompt templates for summarization are defined by `PromptTemplate`.

        Example:
        >>> summarize_via_openai(self, "my long CTI report")
        "This is the summarized content."

        """
        text_splitter = TokenTextSplitter(encoding_name="gpt3", 
                                          # model_name=self.model, 
                                          model_name="gpt-3.5-turbo",
                                          chunk_size=MAXLEN-PROMPTLEN-SUMMARYLEN)
        
        if not text:
            print(f"Warning: empty text submitted. Returning what must be returned")
            return None

        # save the text temporarily XXX FIXME, actually not needed XXX
        temp_file_name = save_string_to_custom_temp_file(text)
        print(f"Wrote contents to {temp_file_name}")

        try:
            loader = TextLoader(temp_file_name, autodetect_encoding=True) 
            
            # chunk it up, baby
            try:
                docs = loader.load_and_split(text_splitter)
                if debug:
                    print(type(docs))
                    print(f"{len(docs)=}")
                    print(docs)
            except Exception as ex:
                print(f"Error occured when loading via loader: {str(ex)}")
                return {"error": ex}

            if DRY_RUN:
                return {"answer": "in dry-run mode, not summarizing"}

            output_parser = StructuredOutputParser.from_response_schemas(response_schemas)
            format_instructions = output_parser.get_format_instructions()
            if debug:
                print(f'FORMAT INSTRUCTIONS: {format_instructions}')
            
            # now summarize all the chunks with map reduce
            # prompt = PromptTemplate(template=CTI_TEMPLATE_SUMMARIZATION, input_variables=["text", "format_instructions"])
            prompt = PromptTemplate.from_template(template=CTI_TEMPLATE_SUMMARIZATION)
            chain = load_summarize_chain(self.llm, chain_type="map_reduce",
                                        return_intermediate_steps=False,
                                        map_prompt=prompt,
                                        combine_prompt=prompt,
                                        verbose=False)
            response = chain(docs, return_only_outputs=True)
            if debug:
                print(80*"=")
                print(f"Type(response): {type(response)}; Response: {response}")
                print(80*"=")
        
            return dict(output_parser.parse(response['output_text']))
        except Exception as ex:
            print(f"An error occurred with link {link}. Error: {str(ex)}")
            return {"error": str(ex)}