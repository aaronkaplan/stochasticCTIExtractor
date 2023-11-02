from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from summarizer import Summarizer


app = FastAPI(title="Stochastic Alex")


class TextData(BaseModel):
    text: str


# Define your list of valid API keys
valid_api_keys = ["1234test", "5678test"]


# Dependency to validate the API key
def get_valid_api_key(x_api_key: str = Header(None)) -> str:
    if x_api_key not in valid_api_keys:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return x_api_key


@app.post("/summarize", tags=["Manual summarization of a single article"])
async def summarize_text(data: TextData, api_key: str = Depends(get_valid_api_key)):
    """Summarize an article given by {url} . Returns a JSON answer."""
    print(f"About to summarize '{data.text[30:]}'")
    text = data.text

    summarizer = Summarizer() 
    summary = summarizer.summarize_via_openai(text)
    # return JSONResponse(content=summary, status_code=200)
    return summary

