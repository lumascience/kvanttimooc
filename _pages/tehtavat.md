---
title: Tehtävät
---

# Tehtävät

## Tehtävä 1

Millä todennäköisyydellä ohjelma antaa tuloksen 1?

<form id="task1">
<input name="answer" type="radio" value="0"> 0 % <br>
<input name="answer" type="radio" value="25"> 25 % <br>
<input name="answer" type="radio" value="50"> 50 % <br>
<input name="answer" type="radio" value="75"> 75 % <br>
<input name="answer" type="radio" value="100"> 100 % <br>
</form>
<button onclick="test()">Lähetä vastaus</button>

<script>
function test() {
    var answer = document.getElementById("task1").elements["answer"].value;
    if (answer == 50) {
        alert("Oikein!");
    } else {
        alert("Väärin!");
    }
}
</script>
