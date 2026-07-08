# Guion de demo (3-4 min) — Local PII Redactor

## Por qué esta demo es doblemente valiosa
Es una demo para la entrevista **y** una herramienta que usarás de verdad cada día. Une tu ADN de seguridad con el problema nº1 de adopción de LLMs en enterprise: "no podemos mandar nuestros datos fuera".

## Apertura (30s)
> "La primera objeción de cualquier cliente enterprise ante un LLM es la misma que llevo 8 años oyendo en seguridad: '¿y mis datos?'. Esta es la respuesta práctica. Anonimizo en local antes de que nada salga, y mantengo la calidad del mejor modelo. Y no es teoría — lo uso yo con mis notas de reunión."

## Demo en vivo (2 min)
1. **Ejemplo** → cargas un texto con nombre, DNI, tarjeta, email, teléfono, IBAN e IP.
2. **Anonimizar** → aparece el texto limpio con tokens resaltados. "Fíjate: la tarjeta se valida con Luhn, el DNI con su letra de control — no marco números al azar, solo datos reales."
3. Señalar el **badge**: "100% local, nada sale de mi equipo. No hay API key, no hay coste, funciona sin internet."
4. **Copiar limpio** → "Esto es lo que pego en ChatGPT o Claude. El DNI y la tarjeta nunca llegaron a OpenAI."
5. **Rehidratar** → pegas una respuesta con tokens y recupera los valores reales en local.

## El punto que te separa (1 min) — los tres niveles
> "Pero redactar no es un botón mágico de 'ya es seguro'. Por eso clasifico por nivel de sensibilidad:
> - **Nivel 1**: no hay datos sensibles → directo al mejor modelo cloud.
> - **Nivel 2**: hay PII → redacto y uso el modelo cloud. El 80% de los casos.
> - **Nivel 3**: marcadores de confidencialidad (NDA, no público) → ni redactado sale; modelo local o nada.
> Esto es exactamente la política de gobierno de datos que un CISO quiere oír — y yo la estoy *usando*, no solo explicando."

Enseña un texto con "bajo NDA" → salta el aviso Nivel 3 en rojo.

## Puntos técnicos si preguntan
- **Falsos positivos**: "Validación Luhn en tarjetas y letra de control en DNI — no redacto un '2024' o un número de pedido. Los evals miden recall, fugas y falsos positivos: 100% / 0 / 0."
- **Nombres**: "Detección por tratamiento (Sr./Dña.) — precisión alta a propósito. Para más recall metería un NER local (spaCy), pero lo dejo sin dependencias para que corra 100% offline."
- **Re-identificación**: "El riesgo real no es el nombre, es el contexto. Por eso existe el Nivel 3 — la herramienta es honesta sobre su límite."

## Cierre
> "Es la misma arquitectura de guardrails que diseñaría para un cliente, reducida a una herramienta personal. Demuestra que entiendo el blocker de adopción y sé resolverlo — que es el trabajo del SE."
