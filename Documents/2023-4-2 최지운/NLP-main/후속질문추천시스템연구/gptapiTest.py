import os 
import openai
from konlpy.tag import Okt
import re
import pandas as pd
import csv
openai.api_key = "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"

### answer 전처리(데이터셋읽어오기) [임베딩하기 편한 토크나이징 된 <문장형태>로 변환] ###

t = Okt()


def tokenize_to_fullsents(df):

    tok_sentence_forVectorize=[]
    tokenized=[]
    for sentences in df:  #### 전처리및 토크나이징 후 유사도 비교를 위해 다시붙이기
     
        sentences=str(sentences)
        sentences=sentences.replace('\n','')
        sentences=sentences.replace(',','')
        sentences=sentences.replace('"','')
        sentences=sentences.replace("'",'')
        sentences=sentences.replace('-','')
        sentences=sentences.replace('(','')
        sentences=sentences.replace(')','')
        sentences=sentences.replace('.','')
        sentences=sentences.replace('{','')
        sentences=sentences.replace('}','')
        sentences=sentences.replace('`','')


        #print(sentences)
        contents_tokens=t.morphs(sentences)
        tokenized.append(contents_tokens)

    

    for content in tokenized:
        sentence=''
        for word in content:
            sentence=sentence+' '+word
        

        tok_sentence_forVectorize.append(sentence)

    return tok_sentence_forVectorize



### 전체 답변에 대한 키워드 추출 부분

def keyword_extractor_Qanswer_fullanswer(tokenizinedList,idx):
    idx=0 #### gpt로 키워드 뽑는 부분

    answer=str(tokenizinedList[idx]) #토큰화된것중에 타겟질문에 대한 해답을 index로 반환해주는 idx
    #context='' #context로 answer context에 해당되는 manual data 집어넣기(기밀유지코드해당부분)
    prompt=context+answer+' 다음 문단의 문맥을 참고하여, 이 문단이 설명하고 있는 핵심키워드들을 dict자료형으로 뽑아줘'
    completion = openai.ChatCompletion.create(
        model = "gpt-3.5-turbo",
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role":"user","content":prompt}
        ]
    )


    keyword_dict=completion.choices[0].message.content
    # print(type(keyword_dict))
    keyword_dict=eval(keyword_dict) #str->dict type difference

    print(completion.choices[0].message.content)
    return keyword_dict

a={}
final=[]
df=pd.read_csv("후속질문추천시스템연구/JEUS_application-client_final_DB(문단)_0705_new_eng copy.csv",encoding='utf-8',header=None)
df=df[3]
df=df[:10] ## 예시코드에서는 10개만 (본코드시 삭제) <예시 코드>
df_list=df.values.tolist()
tokenizedList=tokenize_to_fullsents(df_list)
print(tokenizedList[0])
a=keyword_extractor_Qanswer_fullanswer(tokenizedList,0)
final.append(list(a.keys()))
print(final[-1])